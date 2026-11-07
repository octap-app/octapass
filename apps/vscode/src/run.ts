// The line typed into the terminal. The terminal's `octapass run` reads the secrets, so no value
// passes through the extension. No `vscode` import.

type Shell = 'posix' | 'powershell' | 'cmd';

function shellFamily(shell: string, platform: NodeJS.Platform): Shell {
  const name = shell.split(/[\\/]/).pop()?.toLowerCase() ?? '';
  if (name.startsWith('pwsh') || name.startsWith('powershell')) {
    return 'powershell';
  }
  if (name === 'cmd.exe' || name === 'cmd') {
    return 'cmd';
  }
  return platform === 'win32' && name === '' ? 'powershell' : 'posix';
}

function program(path: string, shell: Shell): string {
  if (shell === 'posix') {
    return /^[\w./:=@%+,~-]+$/.test(path) ? path : `'${path.replace(/'/g, `'\\''`)}'`;
  }
  if (/^[\w./:\\~-]+$/.test(path)) {
    return path;
  }
  return shell === 'powershell' ? `& '${path.replace(/'/g, "''")}'` : `"${path}"`;
}

/** `octapass run -- <command>`, with the command as the person typed it. */
export function runLine(cliPath: string, command: string, shell: string, platform: NodeJS.Platform): string {
  return `${program(cliPath.trim() || 'octapass', shellFamily(shell, platform))} run -- ${command.trim()}`;
}
