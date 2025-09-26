// Enhanced scanCode function with Python support
async function scanWorkspace(context) {
    if (!vscode.workspace.workspaceFolders) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    const files = await vscode.workspace.findFiles('**/*.{js,ts,py}', '**/node_modules/**', 100);
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `🔍 Scanning ${files.length} files for security issues...`,
        cancellable: false
    }, async (progress) => {
        let totalIssues = 0;
        const scannedFiles = [];
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            progress.report({ 
                increment: (100 / files.length),
                message: `Scanning ${path.basename(file.fsPath)}...`
            });
            
            const document = await vscode.workspace.openTextDocument(file);
            const issues = await scanCodeForIssues(document, context);
            totalIssues += issues;
            scannedFiles.push({
                file: file.fsPath,
                issues: issues
            });
        }
        
        // Save scan event to history
        saveScanEvent(context, {
            type: 'workspace_scan',
            timestamp: new Date().toISOString(),
            filesScanned: files.length,
            totalIssues: totalIssues,
            files: scannedFiles
        });
        
        vscode.window.showInformationMessage(
            `🔍 Workspace scan complete! Found ${totalIssues} security issues across ${files.length} files.`,
            'View History'
        ).then(selection => {
            if (selection === 'View History') {
                viewScanHistory(context);
            }
        });
    });
}

// AI-powered fix generation for all issues
async function generateAIFixForAllIssues(document, issues) {
    const code = document.getText();
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "🤖 AI is generating fixes for all security issues...",
        cancellable: false
    }, async (progress) => {
        try {
            const fixedCode = await getAIFixedCode(code, issues, document.languageId);
            
            const panel = vscode.window.createWebviewPanel(
                'aiFixedCode',
                'AI-Generated Security Fixes',
                vscode.ViewColumn.Two,
                { enableScripts: true }
            );

            panel.webview.html = createFixComparisonHTML(code, fixedCode, issues);
            
            vscode.window.showInformationMessage('🤖 AI fixes generated!', 'Apply All Fixes')
                .then(selection => {
                    if (selection === 'Apply All Fixes') {
                        const editor = vscode.window.activeTextEditor;
                        if (editor && editor.document === document) {
                            editor.edit(editBuilder => {
                                const fullRange = new vscode.Range(
                                    document.positionAt(0),
                                    document.positionAt(code.length)
                                );
                                editBuilder.replace(fullRange, fixedCode);
                            });
                            
                            vscode.window.showInformationMessage('✅ All AI fixes applied!');
                        }
                    }
                });

        } catch (error) {
            console.error('AI fix generation error:', error);
            vscode.window.showErrorMessage(`AI fix generation failed: ${error.message}`);
        }
    });
}

async function getAIFixedCode(code, issues, languageId) {
    const issueDescriptions = issues.map(issue => 
        `- ${issue.check_id}: ${issue.extra.message} (Line ${issue.start.line})`
    ).join('\n');

    const languageSpecific = languageId === 'python' ? 
        `Python security best practices:
- Use secrets module for cryptographic functions
- Avoid eval() and exec() functions
- Use parameterized queries with SQLAlchemy
- Validate inputs with proper type checking
- Use environment variables with python-dotenv
- Implement proper exception handling` :
        `JavaScript/TypeScript security best practices:
- Use bcrypt for password hashing
- Implement JWT properly
- Use helmet.js for security headers
- Validate inputs with joi or similar
- Use parameterized queries
- Implement CSRF protection`;

    const systemPrompt = `You are a cybersecurity expert. Fix all security issues in the provided ${languageId} code while maintaining functionality.

Issues found:
${issueDescriptions}

${languageSpecific}

General guidelines:
- Fix hardcoded secrets by using environment variables
- Add input validation and sanitization
- Use parameterized queries
- Add proper error handling
- Include authorization checks
- Use secure cryptographic functions
- Prevent all injection attacks
- Maintain the original code structure and functionality

Return only the complete fixed code, no explanations.`;

    const requestBody = JSON.stringify({
        model: AI_CONFIG.model,
        messages: [
            {
                role: "system", 
                content: systemPrompt
            },
            {
                role: "user",
                content: `Fix all security issues in this ${languageId} code:\n\n${code}`
            }
        ],
        max_tokens: 2000,
        temperature: 0.2
    });

    return new Promise((resolve, reject) => {
        const options = {
            hostname: AI_CONFIG.baseUrl,
            port: 443,
            path: AI_CONFIG.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AI_CONFIG.apiKey}`,
                'Content-Length': Buffer.byteLength(requestBody)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    
                    if (response.error) {
                        reject(new Error(response.error.message || 'API Error'));
                        return;
                    }

                    if (response.choices && response.choices[0] && response.choices[0].message) {
                        resolve(response.choices[0].message.content.trim());
                    } else {
                        reject(new Error('Unexpected API response format'));
                    }
                } catch (parseError) {
                    reject(new Error(`Failed to parse API response: ${parseError.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(new Error(`Network error: ${error.message}`));
        });

        req.write(requestBody);
        req.end();
    });
}

// Scan History and Metrics
function initializeScanHistory(context) {
    const historyPath = path.join(context.globalStoragePath || context.extensionPath, 'scan-history.json');
    try {
        if (fs.existsSync(historyPath)) {
            const data = fs.readFileSync(historyPath, 'utf8');
            scanHistory = JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading scan history:', error);
        scanHistory = [];
    }
}

function saveScanEvent(context, event) {
    scanHistory.push(event);
    
    // Keep only last 100 events
    if (scanHistory.length > 100) {
        scanHistory = scanHistory.slice(-100);
    }
    
    const historyPath = path.join(context.globalStoragePath || context.extensionPath, 'scan-history.json');
    try {
        // Ensure directory exists
        const dir = path.dirname(historyPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(historyPath, JSON.stringify(scanHistory, null, 2));
    } catch (error) {
        console.error('Error saving scan history:', error);
    }
}

function getEventDetails(event) {
    switch (event.type) {
        case 'security_scan':
            return `Scanned ${event.fileName} - Found ${event.issuesFound || 0} issues`;
        case 'fix_applied':
            return `Applied fix for: ${event.issueType}`;
        case 'prompt_enhancement':
            return `Enhanced prompt: "${event.original?.substring(0, 50)}..."`;
        default:
            return 'Security activity';
    }
}

function scanCode(document, context) {
    scanCodeForIssues(document, context);
}

async function scanCodeForIssues(document, context = null) {
    const code = document.getText();
    const fileExtension = path.extname(document.fileName);
    const tempFile = path.join(os.tmpdir(), `semgrep_temp_${Date.now()}${fileExtension}`);
    
    try {
        fs.writeFileSync(tempFile, code);
        
        let rulesPath = getRulesPath(context);
        if (!fs.existsSync(rulesPath)) {
            createDefaultRules(rulesPath);
        }
        
        return new Promise((resolve, reject) => {
            const semgrepArgs = [
                'scan', 
                '--config', rulesPath, 
                tempFile, 
                '--json', 
                '--quiet',
                '--disable-version-check',
                '--no-git-ignore',
                '--timeout=30'
            ];
            
            const semgrep = spawn('semgrep', semgrepArgs, {
                stdio: ['ignore', 'pipe', 'pipe'],
                env: { 
                    ...process.env, 
                    PYTHONHTTPSVERIFY: '0',
                    CURL_CA_BUNDLE: '',
                    REQUESTS_CA_BUNDLE: ''
                }
            });
            
            let output = '';
            let errorOutput = '';
            
            semgrep.stdout.on('data', (data) => { 
                output += data.toString(); 
            });
            
            semgrep.stderr.on('data', (data) => { 
                errorOutput += data.toString();
            });
            
            semgrep.on('close', (exitCode) => {
                try {
                    fs.unlinkSync(tempFile);
                } catch (e) {
                    console.error('Error deleting temp file:', e);
                }
                
                const filteredErrorOutput = errorOutput
                    .split('\n')
                    .filter(line => !line.includes('x509.decoding'))
                    .filter(line => !line.includes('ca-certs'))
                    .filter(line => !line.includes('trust anchors'))
                    .filter(line => !line.includes('WARNING'))
                    .join('\n')
                    .trim();
                
                if (exitCode === 0 || exitCode === 1 || exitCode === 2) {
                    try {
                        if (output.trim()) {
                            const results = JSON.parse(output);
                            const issueCount = processScanResults(results, document);
                            
                            // Save scan event
                            if (context) {
                                saveScanEvent(context, {
                                    type: 'security_scan',
                                    timestamp: new Date().toISOString(),
                                    fileName: path.basename(document.fileName),
                                    issuesFound: issueCount
                                });
                            }
                            
                            resolve(issueCount);
                        } else {
                            clearDiagnostics(document);
                            resolve(0);
                        }
                    } catch (parseError) {
                        console.error('Error parsing Semgrep output:', parseError);
                        resolve(0);
                    }
                } else {
                    handleSemgrepError(exitCode, filteredErrorOutput, rulesPath);
                    resolve(0);
                }
            });
            
            semgrep.on('error', (error) => {
                console.error('Semgrep spawn error:', error);
                try {
                    fs.unlinkSync(tempFile);
                } catch (e) {}
                
                if (error.code === 'ENOENT') {
                    vscode.window.showErrorMessage('Semgrep not found. Please install: pip install semgrep');
                } else {
                    vscode.window.showErrorMessage(`Semgrep error: ${error.message}`);
                }
                resolve(0);
            });
        });
        
    } catch (error) {
        console.error('Error in scanCode:', error);
        vscode.window.showErrorMessage(`Scan error: ${error.message}`);
        return 0;
    }
}

function processScanResults(results, document) {
    const diagnostics = [];
    const uri = document.uri.toString();
    
    securityIssues.delete(uri);
    
    if (results.results && results.results.length > 0) {
        const issues = [];
        
        results.results.forEach((result, index) => {
            const startLine = Math.max(0, (result.start.line || 1) - 1);
            const startCol = Math.max(0, (result.start.col || 1) - 1);
            const endLine = Math.max(startLine, (result.end.line || startLine + 1) - 1);
            const endCol = Math.max(startCol, result.end.col || startCol + 1);
            
            const range = new vscode.Range(startLine, startCol, endLine, endCol);
            
            const severity = result.extra.severity === 'ERROR' ? 
                vscode.DiagnosticSeverity.Error : 
                vscode.DiagnosticSeverity.Warning;
            
            const diagnostic = new vscode.Diagnostic(
                range,
                result.extra.message,
                severity
            );
            
            diagnostic.code = result.check_id;
            diagnostic.source = 'SecureCodeGuard';
            
            diagnostics.push(diagnostic);
            
            const issue = {
                id: `${uri}_${index}`,
                range,
                message: result.extra.message,
                checkId: result.check_id,
                severity: result.extra.severity,
                lines: result.extra.lines,
                fix: generateQuickFix(result)
            };
            
            issues.push(issue);
        });
        
        securityIssues.set(uri, issues);
        vscode.window.showWarningMessage(
            `Found ${results.results.length} security issue(s) in ${path.basename(document.fileName)}`,
            'View Issues', 'AI Fix All'
        ).then(selection => {
            if (selection === 'View Issues') {
                vscode.commands.executeCommand('workbench.actions.view.problems');
            } else if (selection === 'AI Fix All') {
                generateAIFixForAllIssues(document, results.results);
            }
        });
        
        return results.results.length;
    } else {
        vscode.window.showInformationMessage(`No security issues found in ${path.basename(document.fileName)}`);
        return 0;
    }
    
    diagnosticCollection.set(document.uri, diagnostics);
}

function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Fallback functions for when AI fails
function generateBasicSecurityEnhancement(originalPrompt) {
    const securityEnhancements = [
        "\n🔒 SECURITY REQUIREMENTS:",
        "- Ensure no hardcoded API keys, secrets, or credentials",
        "- Add proper input validation and sanitization",
        "- Include authorization checks for sensitive operations", 
        "- Use environment variables for configuration",
        "- Implement proper error handling without exposing sensitive info",
        "- Add rate limiting for API endpoints if applicable",
        "- Use secure headers and HTTPS where needed",
        "- Validate and sanitize all user inputs"
    ];

    return originalPrompt + "\n\n" + securityEnhancements.join("\n");
}

function showFallbackPrompt(original, enhanced) {
    const panel = vscode.window.createWebviewPanel(
        'fallbackPrompt',
        'Security-Enhanced Prompt (Fallback)',
        vscode.ViewColumn.Two,
        { enableScripts: true }
    );

    panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; padding: 15px; border-radius: 5px; }
                .original { background-color: #f0f0f0; }
                .enhanced { background-color: #e8f5e8; }
                .fallback-notice { background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="fallback-notice">
                ⚠️ AI enhancement failed, using rule-based enhancement instead.
            </div>
            <h1>🔒 Security-Enhanced Prompt</h1>
            <div class="section original">
                <h3>Original:</h3>
                <pre>${original}</pre>
            </div>
            <div class="section enhanced">
                <h3>Enhanced:</h3>
                <pre>${enhanced}</pre>
            </div>
        </body>
        </html>
    `;
}

// Utility functions
function generateQuickFix(result) {
    const checkId = result.check_id;
    
    switch (checkId) {
        case 'hardcoded-api-key':
        case 'python-hardcoded-secret':
            return {
                title: 'Replace with environment variable',
                kind: vscode.CodeActionKind.QuickFix,
                edit: {
                    newText: checkId === 'python-hardcoded-secret' ? 'os.getenv("API_KEY")' : 'process.env.API_KEY',
                    description: 'Replace hardcoded secret with environment variable'
                }
            };
        case 'missing-auth-check':
        case 'python-missing-auth-flask':
            return {
                title: 'Add authorization check',
                kind: vscode.CodeActionKind.QuickFix,
                edit: {
                    newText: checkId === 'python-missing-authorization' ?
                        'if not session.get("user_authenticated"):\n        return "Unauthorized", 401\n    ' :
                        'if (!req.user || !req.user.authorized) { return res.status(401).json({error: "Unauthorized"}); }\n    ',
                    description: 'Add basic authorization check'
                }
            };
        default:
            return {
                title: 'View security documentation',
                kind: vscode.CodeActionKind.QuickFix,
                command: {
                    title: 'Open Security Docs',
                    command: 'vscode.open',
                    arguments: ['https://owasp.org/www-project-top-ten/']
                }
            };
    }
}

function clearDiagnostics(document) {
    diagnosticCollection.set(document.uri, []);
    securityIssues.delete(document.uri.toString());
}

function getRulesPath(context) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    
    if (workspaceFolder) {
        const workspaceRulesPath = path.join(workspaceFolder.uri.fsPath, 'rules.yaml');
        if (fs.existsSync(workspaceRulesPath)) {
            return workspaceRulesPath;
        }
    }
    
    if (context && context.extensionPath) {
        return path.join(context.extensionPath, 'rules.yaml');
    }
    
    return path.join(os.tmpdir(), 'securecodeguard-rules.yaml');
}

function createDefaultRules(rulesPath) {
    const defaultRules = `rules:
  - id: hardcoded-api-key
    pattern-either:
      - pattern: |
          const $VAR = "$VALUE"
      - pattern: |
          let $VAR = "$VALUE"
      - pattern: |
          var $VAR = "$VALUE"
    pattern-where:
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(api.?key|secret|token|password|pwd|credential)
      - metavariable-regex:
          metavariable: $VALUE
          regex: .{8,}
    message: "Hardcoded API key or secret detected. Use environment variables instead."
    languages: [javascript, typescript]
    severity: ERROR

  - id: hardcoded-secret
    patterns:
      - pattern: $VAR = "$SECRET"
      - metavariable-pattern:
          metavariable: $SECRET
          pattern: /(?i)(api[_-]?key|token|secret|passwd|password|credentials)/
    message: "Possible hardcoded secret detected"
    severity: ERROR
    languages: [python]

  - id: missing-auth-check
    pattern-either:
      - pattern: |
          function $FUNC(...) { 
            $...BODY
          }
      - pattern: |
          const $FUNC = (...) => {
            $...BODY  
          }
    pattern-where:
      - metavariable-regex:
          metavariable: $FUNC
          regex: (?i)(login|auth|admin|delete|create|update|remove)
    pattern-not-inside: |
      if ($AUTH) { ... }
    message: "Function handles sensitive operations but lacks authorization checks."
    languages: [javascript, typescript]
    severity: WARNING

  - id: missing-authorization
    pattern-either:
      - pattern: |
          @app.route($ROUTE)
          def $FUNC(...):
              ...
    message: "Route may be missing authorization check"
    severity: WARNING
    languages: [python]

  - id: python-eval-usage
    pattern-either:
      - pattern: eval($ARG)
      - pattern: exec($ARG)
    message: "Avoid using eval() or exec() as they can execute arbitrary code."
    languages: [python]
    severity: ERROR`;
    
    try {
        fs.writeFileSync(rulesPath, defaultRules);
        console.log('Created default rules.yaml at:', rulesPath);
    } catch (error) {
        console.error('Error creating default rules:', error);
    }
}

function handleSemgrepError(exitCode, errorOutput, rulesPath) {
    console.error('Semgrep failed with exit code:', exitCode);
    
    if (errorOutput.includes('command not found') || errorOutput.includes('not recognized')) {
        vscode.window.showErrorMessage('Semgrep not found. Install with: pip install semgrep');
    } else if (errorOutput.includes('No such file')) {
        vscode.window.showErrorMessage(`Rules file not found: ${rulesPath}`);
    } else {
        vscode.window.showErrorMessage(`Semgrep scan failed: ${errorOutput || 'Unknown error'}`);
    }
}

async function applySecurityFix(args) {
    const { uri, range, fix } = args;
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uri));
    const editor = await vscode.window.showTextDocument(document);
    
    if (fix && fix.edit) {
        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, range, fix.edit.newText);
        await vscode.workspace.applyEdit(edit);
        
        setTimeout(() => {
            scanCode(document);
        }, 1000);
        
        vscode.window.showInformationMessage('Security fix applied! Rescanning...');
    }
}

// Code Action Provider for Quick Fixes
class SecurityCodeActionProvider {
    provideCodeActions(document, range, context, token) {
        const actions = [];
        const uri = document.uri.toString();
        const issues = securityIssues.get(uri) || [];
        
        const relevantIssues = issues.filter(issue => issue.range.intersection(range));
        
        relevantIssues.forEach(issue => {
            const action = new vscode.CodeAction(
                issue.fix.title,
                issue.fix.kind
            );
            
            if (issue.fix.edit) {
                action.edit = new vscode.WorkspaceEdit();
                action.edit.replace(document.uri, issue.range, issue.fix.edit.newText);
            }
            
            if (issue.fix.command) {
                action.command = issue.fix.command;
            }
            
            actions.push(action);
        });
        
        return actions;
    }
}

function deactivate() {
    console.log('SecureCodeGuard is deactivated.');
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};// The module 'vscode' contains the VS Code extensibility API
const vscode = require('vscode');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');

// Global variables for diagnostics and fixes
let diagnosticCollection;
let securityIssues = new Map();
let scanHistory = [];
//
// AI Configuration for GroqCloud
const AI_CONFIG = {
    apiKey: '',//api key here use your own api key from groqcloud
    model: 'openai/gpt-oss-120b', // Using Groq's model
    baseUrl: 'api.groq.com', // GroqCloud endpoint
    path: '/openai/v1/chat/completions'
};

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('SecureCodeGuard is now activated!');

    // Create diagnostic collection for showing issues in Problems panel
    diagnosticCollection = vscode.languages.createDiagnosticCollection('securecodeguard');
    context.subscriptions.push(diagnosticCollection);

    // Initialize scan history storage
    initializeScanHistory(context);

    // Register commands
    const enhancePromptCommand = vscode.commands.registerCommand('securecodeguard.enhancePrompt', () => enhancePromptWithAI(context));
    const scanWorkspaceCommand = vscode.commands.registerCommand('securecodeguard.scanWorkspace', () => scanWorkspace(context));
    const applyFixCommand = vscode.commands.registerCommand('securecodeguard.applyFix', applySecurityFix);
    const viewHistoryCommand = vscode.commands.registerCommand('securecodeguard.viewHistory', () => viewScanHistory(context));
    const generateSecureCodeCommand = vscode.commands.registerCommand('securecodeguard.generateSecureCode', () => generateSecureCodeWithAI(context));

    context.subscriptions.push(enhancePromptCommand, scanWorkspaceCommand, applyFixCommand, viewHistoryCommand, generateSecureCodeCommand);

    // Hook into save event
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((document) => {
        console.log('Save event triggered for:', document.fileName, 'Language:', document.languageId);
        if (isSupportedFile(document)) {
            scanCode(document, context);
            vscode.window.showInformationMessage('File saved - scanning for security issues...');
        }
    }));

    // Hook into text change event with throttle
    let timeout;
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        if (isSupportedFile(event.document)) {
            if (timeout) clearTimeout(timeout);
            timeout = setTimeout(() => {
                scanCode(event.document, context);
            }, 3000);
        }
    }));

    // Register code action provider for quick fixes
    const jsProvider = vscode.languages.registerCodeActionsProvider(
        [{ scheme: 'file', language: 'javascript' }, { scheme: 'file', language: 'typescript' }],
        new SecurityCodeActionProvider(),
        {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        }
    );
    
    const pythonProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file', language: 'python' },
        new SecurityCodeActionProvider(),
        {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        }
    );
    
    context.subscriptions.push(jsProvider, pythonProvider);

    vscode.window.showInformationMessage('SecureCodeGuard with AI is active! 🤖🔒');
}

function isSupportedFile(document) {
    return document.languageId === 'javascript' || 
           document.languageId === 'typescript' ||
           document.languageId === 'python' ||
           document.fileName.endsWith('.js') ||
           document.fileName.endsWith('.ts') ||
           document.fileName.endsWith('.py');
}

// AI-Enhanced Prompt Enhancement
async function enhancePromptWithAI(context) {
    const prompt = await vscode.window.showInputBox({
        placeHolder: 'Enter your coding prompt here...',
        prompt: 'Enter the prompt you want to enhance with AI-powered security considerations',
        ignoreFocusOut: true
    });

    if (!prompt) {
        return;
    }

    // Show loading message
    const progress = vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "🤖 AI is enhancing your prompt with security best practices...",
        cancellable: false
    }, async (progress) => {
        try {
            // Get AI-enhanced prompt
            const enhancedPrompt = await getAIEnhancedPrompt(prompt);
            
            // Show the enhanced prompt
            const panel = vscode.window.createWebviewPanel(
                'aiEnhancedPrompt',
                'AI-Enhanced Security Prompt',
                vscode.ViewColumn.Two,
                { enableScripts: true }
            );

            panel.webview.html = createAIPromptEnhancementHTML(prompt, enhancedPrompt);
            
            // Save to history
            saveScanEvent(context, {
                type: 'prompt_enhancement',
                timestamp: new Date().toISOString(),
                original: prompt,
                enhanced: enhancedPrompt.substring(0, 200) + '...'
            });

            vscode.window.showInformationMessage('✨ AI-enhanced prompt ready!');

        } catch (error) {
            console.error('AI enhancement error:', error);
            vscode.window.showErrorMessage(`AI enhancement failed: ${error.message}`);
            
            // Fallback to rule-based enhancement
            const fallbackPrompt = generateBasicSecurityEnhancement(prompt);
            showFallbackPrompt(prompt, fallbackPrompt);
        }
    });
}

// AI API Call Function for GroqCloud
async function getAIEnhancedPrompt(originalPrompt) {
    const systemPrompt = `You are a cybersecurity expert helping developers write secure code. 
Your task is to enhance coding prompts by adding specific security requirements and best practices.

Guidelines:
- Add specific security requirements relevant to the request
- Include OWASP best practices where applicable  
- Suggest secure coding patterns
- Mention specific security libraries or frameworks
- Add input validation, authorization, and error handling requirements
- Keep the original intent but make it security-focused
- Be specific and actionable

Original prompt: "${originalPrompt}"

Enhanced prompt with security requirements:`;

    const requestBody = JSON.stringify({
        model: AI_CONFIG.model,
        messages: [
            {
                role: "system", 
                content: systemPrompt
            },
            {
                role: "user",
                content: `Please enhance this coding prompt with comprehensive security requirements: "${originalPrompt}"`
            }
        ],
        max_tokens: 800,
        temperature: 0.7
    });

    return new Promise((resolve, reject) => {
        const options = {
            hostname: AI_CONFIG.baseUrl,
            port: 443,
            path: AI_CONFIG.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AI_CONFIG.apiKey}`,
                'Content-Length': Buffer.byteLength(requestBody)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    
                    if (response.error) {
                        reject(new Error(response.error.message || 'API Error'));
                        return;
                    }

                    if (response.choices && response.choices[0] && response.choices[0].message) {
                        resolve(response.choices[0].message.content.trim());
                    } else {
                        reject(new Error('Unexpected API response format'));
                    }
                } catch (parseError) {
                    reject(new Error(`Failed to parse API response: ${parseError.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(new Error(`Network error: ${error.message}`));
        });

        req.write(requestBody);
        req.end();
    });
}

// Generate Secure Code with AI
async function generateSecureCodeWithAI(context) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('Please open a file first');
        return;
    }

    const selection = editor.selection;
    const selectedText = editor.document.getText(selection);
    
    if (!selectedText) {
        vscode.window.showErrorMessage('Please select some code to secure');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "🤖 AI is generating secure version of your code...",
        cancellable: false
    }, async (progress) => {
        try {
            const secureCode = await generateSecureCodeVersion(selectedText, editor.document.languageId);
            
            // Show comparison
            const panel = vscode.window.createWebviewPanel(
                'secureCodeComparison',
                'Secure Code Generation',
                vscode.ViewColumn.Two,
                { enableScripts: true }
            );

            panel.webview.html = createSecureCodeComparisonHTML(selectedText, secureCode);
            
            vscode.window.showInformationMessage('🔒 Secure code version generated!', 'Apply Changes')
                .then(selection => {
                    if (selection === 'Apply Changes') {
                        editor.edit(editBuilder => {
                            editBuilder.replace(editor.selection, secureCode);
                        });
                    }
                });

        } catch (error) {
            console.error('Secure code generation error:', error);
            vscode.window.showErrorMessage(`Secure code generation failed: ${error.message}`);
        }
    });
}

async function generateSecureCodeVersion(insecureCode, languageId) {
    const languageSpecific = languageId === 'python' ? 
        `Focus on Python-specific security:
- Use secrets module for cryptographic functions
- Avoid eval() and exec() functions
- Use parameterized queries with SQLAlchemy or similar
- Validate inputs with proper type checking
- Use environment variables with python-dotenv
- Implement proper exception handling
- Use secure file operations with proper permissions` :
        `Focus on JavaScript/TypeScript security:
- Use bcrypt for password hashing
- Implement JWT properly with secret rotation
- Use helmet.js for security headers
- Validate inputs with joi or similar
- Use parameterized queries
- Implement CSRF protection
- Use secure session management`;

    const systemPrompt = `You are a cybersecurity expert. Your task is to rewrite insecure code to make it secure while maintaining the same functionality.

${languageSpecific}

General guidelines:
- Remove hardcoded secrets and use environment variables
- Add input validation and sanitization
- Add proper error handling
- Include authorization checks
- Use secure cryptographic functions
- Prevent injection attacks
- Add rate limiting where appropriate

Return ONLY the secure code, no explanations.`;

    const requestBody = JSON.stringify({
        model: AI_CONFIG.model,
        messages: [
            {
                role: "system", 
                content: systemPrompt
            },
            {
                role: "user",
                content: `Please rewrite this insecure ${languageId} code to make it secure:\n\n${insecureCode}`
            }
        ],
        max_tokens: 1000,
        temperature: 0.3
    });

    return new Promise((resolve, reject) => {
        const options = {
            hostname: AI_CONFIG.baseUrl,
            port: 443,
            path: AI_CONFIG.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AI_CONFIG.apiKey}`,
                'Content-Length': Buffer.byteLength(requestBody)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    
                    if (response.error) {
                        reject(new Error(response.error.message || 'API Error'));
                        return;
                    }

                    if (response.choices && response.choices[0] && response.choices[0].message) {
                        resolve(response.choices[0].message.content.trim());
                    } else {
                        reject(new Error('Unexpected API response format'));
                    }
                } catch (parseError) {
                    reject(new Error(`Failed to parse API response: ${parseError.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(new Error(`Network error: ${error.message}`));
        });

        req.write(requestBody);
        req.end();
    });
}

// Updated UI functions with improved styling
function createAIPromptEnhancementHTML(original, enhanced) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI-Enhanced Security Prompt</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0;
                    padding: 20px; 
                    line-height: 1.6; 
                    background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
                    color: #ffffff;
                    min-height: 100vh;
                }
                .container { 
                    max-width: 1000px; 
                    margin: 0 auto; 
                    padding: 20px;
                }
                h1 {
                    color: #ffffff;
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 30px;
                    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                }
                .section { 
                    margin: 25px 0; 
                    padding: 25px; 
                    border-radius: 12px; 
                    border-left: 5px solid #00d4ff; 
                    background: rgba(0, 0, 0, 0.7);
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }
                .original { 
                    border-left-color: #ffa500; 
                    background: rgba(40, 30, 20, 0.8);
                }
                .enhanced { 
                    border-left-color: #00ff88; 
                    background: rgba(20, 40, 30, 0.8);
                }
                .ai-badge { 
                    background: linear-gradient(45deg, #00d4ff, #7b68ee);
                    color: #ffffff;
                    padding: 8px 16px;
                    border-radius: 25px;
                    font-size: 12px;
                    font-weight: bold;
                    display: inline-block;
                    margin-bottom: 15px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    box-shadow: 0 4px 12px rgba(0, 212, 255, 0.3);
                }
                .title { 
                    font-size: 20px; 
                    font-weight: bold; 
                    margin-bottom: 20px; 
                    color: #ffffff; 
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .content { 
                    white-space: pre-wrap; 
                    font-family: 'Monaco', 'Menlo', 'Courier New', monospace; 
                    background: #000000;
                    color: #ffffff;
                    padding: 20px; 
                    border-radius: 8px; 
                    border: 2px solid rgba(255, 255, 255, 0.1);
                    font-size: 14px;
                    line-height: 1.6;
                    box-shadow: inset 0 2px 8px rgba(0,0,0,0.3);
                }
                .copy-btn { 
                    background: linear-gradient(45deg, #00d4ff, #7b68ee); 
                    color: #ffffff; 
                    border: none; 
                    padding: 14px 24px; 
                    border-radius: 8px; 
                    cursor: pointer; 
                    margin-top: 20px;
                    font-weight: bold;
                    font-size: 14px;
                    transition: all 0.3s ease;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .copy-btn:hover { 
                    transform: translateY(-2px);
                    box-shadow: 0 8px 20px rgba(0, 212, 255, 0.4);
                    background: linear-gradient(45deg, #00b8e6, #6a5acd);
                }
                .stats {
                    background: rgba(0, 0, 0, 0.6);
                    color: #ffffff;
                    padding: 15px;
                    border-radius: 6px;
                    margin-top: 15px;
                    font-size: 13px;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    backdrop-filter: blur(5px);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🤖🔒 AI-Enhanced Security Prompt</h1>
                
                <div class="section original">
                    <div class="title">
                        📝 Original Prompt:
                    </div>
                    <div class="content">${original}</div>
                    <div class="stats">Length: ${original.length} characters</div>
                </div>
                
                <div class="section enhanced">
                    <div class="ai-badge">🤖 AI-POWERED</div>
                    <div class="title">
                        🔒 AI-Enhanced Security Prompt:
                    </div>
                    <div class="content">${enhanced}</div>
                    <button class="copy-btn" onclick="copyToClipboard()">📋 Copy AI-Enhanced Prompt</button>
                    <div class="stats">
                        Enhanced length: ${enhanced.length} characters | 
                        Security additions: ${enhanced.length - original.length} characters
                    </div>
                </div>
            </div>
            
            <script>
                function copyToClipboard() {
                    const text = \`${enhanced.replace(/`/g, '\\`')}\`;
                    navigator.clipboard.writeText(text).then(() => {
                        const btn = document.querySelector('.copy-btn');
                        const originalText = btn.textContent;
                        btn.textContent = '✅ Copied!';
                        btn.style.background = 'linear-gradient(45deg, #00ff88, #32cd32)';
                        setTimeout(() => {
                            btn.textContent = originalText;
                            btn.style.background = 'linear-gradient(45deg, #00d4ff, #7b68ee)';
                        }, 2000);
                    });
                }
            </script>
        </body>
        </html>
    `;
}

function createSecureCodeComparisonHTML(original, secure) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Code Generation</title>
            <style>
                body { 
                    font-family: 'Segoe UI', sans-serif; 
                    margin: 0;
                    padding: 20px; 
                    line-height: 1.6; 
                    background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
                    color: #ffffff;
                    min-height: 100vh;
                }
                .container { 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    padding: 20px;
                }
                h1 { 
                    color: #ffffff; 
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 30px;
                    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                }
                .ai-badge {
                    background: linear-gradient(45deg, #00d4ff, #7b68ee);
                    color: #ffffff;
                    padding: 8px 16px;
                    border-radius: 25px;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-left: 15px;
                }
                .comparison { 
                    display: flex; 
                    gap: 25px; 
                    height: 75vh;
                }
                .code-section { 
                    flex: 1; 
                    display: flex; 
                    flex-direction: column;
                }
                .section-title { 
                    font-size: 18px; 
                    font-weight: bold; 
                    padding: 15px 20px; 
                    border-radius: 8px 8px 0 0; 
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: #ffffff;
                }
                .original-title { 
                    background: linear-gradient(45deg, #ff4757, #ff3838);
                }
                .fixed-title { 
                    background: linear-gradient(45deg, #2ed573, #00ff88);
                }
                .code { 
                    font-family: 'Monaco', 'Menlo', 'Courier New', monospace; 
                    background: #000000;
                    color: #ffffff;
                    padding: 25px; 
                    border: 2px solid rgba(255, 255, 255, 0.1);
                    border-radius: 0 0 8px 8px;
                    white-space: pre-wrap;
                    font-size: 14px;
                    line-height: 1.5;
                    overflow-y: auto;
                    flex: 1;
                    box-shadow: inset 0 2px 8px rgba(0,0,0,0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                    🤖🔒 AI-Generated Security Fixes
                    <span class="ai-badge">AI-POWERED</span>
                </h1>
                
                <div class="comparison">
                    <div class="code-section">
                        <div class="section-title original-title">
                            ⚠️ Original Code (Insecure)
                        </div>
                        <div class="code">${escapeHtml(original)}</div>
                    </div>
                    <div class="code-section">
                        <div class="section-title fixed-title">
                            🔒 AI-Generated Secure Code
                        </div>
                        <div class="code">${escapeHtml(secure)}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `;
}

function createFixComparisonHTML(original, fixed, issues) {
    const issueList = issues.map(issue => 
        `<li><strong style="color: #ff4757;">${issue.check_id}</strong>: <span style="color: #ffffff;">${issue.extra.message}</span> <span style="color: #70a1ff;">(Line ${issue.start.line})</span></li>`
    ).join('');

    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Security Fixes</title>
            <style>
                body { 
                    font-family: 'Segoe UI', sans-serif; 
                    margin: 0;
                    padding: 20px; 
                    line-height: 1.6; 
                    background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
                    color: #ffffff;
                    min-height: 100vh;
                }
                .container { 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    padding: 20px;
                }
                h1 {
                    color: #ffffff;
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 30px;
                    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                }
                .ai-badge {
                    background: linear-gradient(45deg, #00d4ff, #7b68ee);
                    color: #ffffff;
                    padding: 8px 16px;
                    border-radius: 25px;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-left: 15px;
                }
                .issues-summary { 
                    background: rgba(0, 0, 0, 0.7);
                    border: 2px solid #ffa500;
                    border-radius: 12px; 
                    padding: 25px; 
                    margin: 25px 0; 
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                }
                .issues-summary h3 {
                    color: #ffa500;
                    margin-top: 0;
                    font-size: 20px;
                }
                .issues-summary ul {
                    color: #ffffff;
                    padding-left: 20px;
                }
                .issues-summary li {
                    margin: 10px 0;
                    font-size: 14px;
                }
                .comparison { 
                    display: flex; 
                    gap: 25px; 
                    height: 70vh; 
                }
                .code-section { 
                    flex: 1; 
                    display: flex; 
                    flex-direction: column; 
                }
                .section-title { 
                    font-size: 18px; 
                    font-weight: bold; 
                    padding: 15px 20px; 
                    border-radius: 8px 8px 0 0; 
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: #ffffff;
                }
                .original-title { 
                    background: linear-gradient(45deg, #ff4757, #ff3838);
                }
                .fixed-title { 
                    background: linear-gradient(45deg, #2ed573, #00ff88);
                }
                .code { 
                    font-family: 'Monaco', 'Menlo', 'Courier New', monospace; 
                    background: #000000;
                    color: #ffffff;
                    padding: 25px; 
                    border: 2px solid rgba(255, 255, 255, 0.1);
                    border-radius: 0 0 8px 8px;
                    white-space: pre-wrap;
                    font-size: 14px;
                    line-height: 1.5;
                    overflow-y: auto;
                    flex: 1;
                    box-shadow: inset 0 2px 8px rgba(0,0,0,0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                    🤖🔒 AI-Generated Security Fixes
                    <span class="ai-badge">AI-POWERED</span>
                </h1>
                
                <div class="issues-summary">
                    <h3>🚨 Issues Fixed:</h3>
                    <ul>${issueList}</ul>
                </div>
                
                <div class="comparison">
                    <div class="code-section">
                        <div class="section-title original-title">
                            ⚠️ Original Code (${issues.length} issues)
                        </div>
                        <div class="code">${escapeHtml(original)}</div>
                    </div>
                    <div class="code-section">
                        <div class="section-title fixed-title">
                            ✅ AI-Fixed Secure Code
                        </div>
                        <div class="code">${escapeHtml(fixed)}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `;
}

function viewScanHistory(context) {
    const panel = vscode.window.createWebviewPanel(
        'scanHistory',
        'Security Scan History & Metrics',
        vscode.ViewColumn.Two,
        { enableScripts: true }
    );

    // Calculate metrics
    const totalScans = scanHistory.filter(h => h.type === 'security_scan').length;
    const totalIssuesFound = scanHistory.reduce((sum, h) => sum + (h.issuesFound || 0), 0);
    const totalFixesApplied = scanHistory.filter(h => h.type === 'fix_applied').length;
    const promptEnhancements = scanHistory.filter(h => h.type === 'prompt_enhancement').length;

    const historyHtml = scanHistory.slice(-20).map(event => `
        <div class="history-item">
            <div class="event-type">${event.type.replace('_', ' ').toUpperCase()}</div>
            <div class="event-time">${new Date(event.timestamp).toLocaleString()}</div>
            <div class="event-details">${getEventDetails(event)}</div>
        </div>
    `).join('');

    panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0;
                    padding: 20px; 
                    background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
                    color: #ffffff;
                    min-height: 100vh;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                h1, h2 { 
                    color: #ffffff; 
                    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                }
                h1 {
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 30px;
                }
                .metrics { 
                    display: flex; 
                    gap: 20px; 
                    margin: 30px 0; 
                    flex-wrap: wrap;
                }
                .metric { 
                    background: linear-gradient(45deg, #00d4ff, #7b68ee);
                    color: #ffffff; 
                    padding: 25px; 
                    border-radius: 12px; 
                    text-align: center; 
                    flex: 1;
                    min-width: 200px;
                    box-shadow: 0 8px 32px rgba(0, 212, 255, 0.3);
                    backdrop-filter: blur(10px);
                }
                .metric-number { 
                    font-size: 32px; 
                    font-weight: bold; 
                    display: block;
                    margin-bottom: 8px;
                }
                .metric-label { 
                    font-size: 14px; 
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    opacity: 0.9;
                }
                .history-section {
                    background: rgba(0, 0, 0, 0.7);
                    border-radius: 12px;
                    padding: 25px;
                    margin-top: 30px;
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }
                .history-item { 
                    border: 1px solid rgba(255, 255, 255, 0.2); 
                    margin: 15px 0; 
                    padding: 20px; 
                    border-radius: 8px; 
                    background: rgba(255, 255, 255, 0.05);
                    backdrop-filter: blur(5px);
                }
                .event-type { 
                    font-weight: bold; 
                    color: #00d4ff; 
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .event-time { 
                    font-size: 12px; 
                    color: #ffffff; 
                    opacity: 0.7;
                    margin: 8px 0;
                }
                .event-details { 
                    margin-top: 10px; 
                    color: #ffffff;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📊 Security Metrics Dashboard</h1>
                
                <div class="metrics">
                    <div class="metric">
                        <span class="metric-number">${totalScans}</span>
                        <div class="metric-label">Security Scans</div>
                    </div>
                    <div class="metric">
                        <span class="metric-number">${totalIssuesFound}</span>
                        <div class="metric-label">Issues Found</div>
                    </div>
                    <div class="metric">
                        <span class="metric-number">${totalFixesApplied}</span>
                        <div class="metric-label">Fixes Applied</div>
                    </div>
                    <div class="metric">
                        <span class="metric-number">${promptEnhancements}</span>
                        <div class="metric-label">AI Enhancements</div>
                    </div>
                </div>
                
                <div class="history-section">
                    <h2>📋 Recent Activity</h2>
                    ${historyHtml}
                </div>
            </div>
        </body>
        </html>
    `;
}