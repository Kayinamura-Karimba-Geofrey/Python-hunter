/**
 * Python Hunter VS Code Language Server Extension.
 *
 * Connects to 'python-hunter lsp' for real-time security diagnostics,
 * supply-chain inspections, and one-click quick fixes.
 */

const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');
const net = require('net');

let client;

function activate(context) {
  const config = vscode.workspace.getConfiguration('pythonHunter');
  if (!config.get('enable', true)) {
    return;
  }

  const execPath = config.get('executablePath', 'python-hunter');
  const tcpPort = config.get('tcpPort', 0);

  let serverOptions;
  if (tcpPort > 0) {
    // Connect to running LSP daemon over TCP
    serverOptions = () => {
      const socket = net.connect({ port: tcpPort, host: '127.0.0.1' });
      return Promise.resolve({
        reader: socket,
        writer: socket,
      });
    };
  } else {
    // Launch 'python-hunter lsp --stdio' directly
    serverOptions = {
      run: {
        command: execPath,
        args: ['lsp', '--stdio'],
        transport: TransportKind.stdio,
      },
      debug: {
        command: execPath,
        args: ['lsp', '--stdio'],
        transport: TransportKind.stdio,
      },
    };
  }

  // Document selectors for all supported files
  const clientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'python' },
      { scheme: 'file', language: 'pip-requirements' },
      { scheme: 'file', language: 'toml' },
      { scheme: 'file', language: 'json' },
      { scheme: 'file', pattern: '**/requirements*.txt' },
      { scheme: 'file', pattern: '**/package.json' },
      { scheme: 'file', pattern: '**/pyproject.toml' },
      { scheme: 'file', pattern: '**/.vscode/tasks.json' },
      { scheme: 'file', pattern: '**/.github/workflows/*.{yml,yaml}' },
    ],
    synchronize: {
      fileEvents: [
        vscode.workspace.createFileSystemWatcher('**/requirements*.txt'),
        vscode.workspace.createFileSystemWatcher('**/package.json'),
        vscode.workspace.createFileSystemWatcher('**/pyproject.toml'),
        vscode.workspace.createFileSystemWatcher('**/.vscode/tasks.json'),
      ],
    },
  };

  client = new LanguageClient(
    'pythonHunterLsp',
    'Python Hunter Security Language Server',
    serverOptions,
    clientOptions
  );

  client.start();

  // Register interactive extension commands
  context.subscriptions.push(
    vscode.commands.registerCommand('python-hunter.scanWorkspace', async () => {
      const term = vscode.window.createTerminal('Python Hunter Scan');
      term.show();
      term.sendText(`${execPath} scan .`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('python-hunter.fixDependencies', async () => {
      const term = vscode.window.createTerminal('Python Hunter Fix');
      term.show();
      term.sendText(`${execPath} fix .`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('python-hunter.launchTui', async () => {
      const term = vscode.window.createTerminal('Python Hunter TUI');
      term.show();
      term.sendText(`${execPath} tui .`);
    })
  );
}

function deactivate() {
  if (!client) {
    return undefined;
  }
  return client.stop();
}

module.exports = {
  activate,
  deactivate,
};
