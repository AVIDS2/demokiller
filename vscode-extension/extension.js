const vscode = require('vscode');
const { execSync } = require('child_process');
const path = require('path');

let statusBarItem;

function activate(context) {
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'demokiller.inspect';
  context.subscriptions.push(statusBarItem);

  const inspectCmd = vscode.commands.registerCommand('demokiller.inspect', async () => {
    await runInspection();
  });
  context.subscriptions.push(inspectCmd);

  vscode.workspace.onDidSaveTextDocument((doc) => {
    const config = vscode.workspace.getConfiguration('demokiller');
    if (config.get('runOnSave') && doc.fileName.endsWith('.ts')) {
      runInspection();
    }
  });

  // Run on activation
  setTimeout(() => runInspection(), 2000);
}

async function runInspection() {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) return;

  statusBarItem.text = '$(sync~spin) Demo Killer...';
  statusBarItem.show();

  try {
    const output = execSync('npx demokiller inspect . --json', {
      cwd: workspaceRoot, timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe']
    }).toString();
    const report = JSON.parse(output);
    const blockers = report.findings.filter(f => f.severity === 'blocker').length;

    if (blockers > 0) {
      statusBarItem.text = `$(error) ${blockers} blockers — ${report.verdict}`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (report.findings.length > 0) {
      statusBarItem.text = `$(warning) ${report.findings.length} findings`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      statusBarItem.text = '$(check) Production Candidate';
      statusBarItem.backgroundColor = undefined;
    }
  } catch (e) {
    statusBarItem.text = '$(error) Demo Killer failed';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
