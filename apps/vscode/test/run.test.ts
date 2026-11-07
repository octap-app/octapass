import { describe, expect, it } from 'vitest';
import { runLine } from '../src/run';

describe('runLine', () => {
  it('leaves the command as typed', () => {
    expect(runLine('octapass', '  npm start -- --port 3000 ', '/bin/zsh', 'darwin')).toBe(
      'octapass run -- npm start -- --port 3000',
    );
  });

  it('falls back to octapass', () => {
    expect(runLine('  ', 'x', '/bin/bash', 'linux')).toBe('octapass run -- x');
  });

  it('keeps a plain path and a home path unquoted', () => {
    expect(runLine('/opt/bin/octapass', 'x', '/bin/bash', 'linux')).toBe('/opt/bin/octapass run -- x');
    expect(runLine('~/bin/octapass', 'x', '/bin/bash', 'linux')).toBe('~/bin/octapass run -- x');
  });

  it('quotes the program for the shell in use', () => {
    expect(runLine("/my tools/it's/octapass", 'x', '/bin/zsh', 'darwin')).toBe(`'/my tools/it'\\''s/octapass' run -- x`);
    expect(runLine('$(touch pwned)', 'x', '/bin/bash', 'linux')).toBe(`'$(touch pwned)' run -- x`);
    const windows = 'C:\\Program Files\\Octa Pass\\octapass.exe';
    expect(runLine(windows, 'x', 'C:\\Windows\\System32\\cmd.exe', 'win32')).toBe(`"${windows}" run -- x`);
    expect(runLine(windows, 'x', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', 'win32')).toBe(`& '${windows}' run -- x`);
    expect(runLine(windows, 'x', '', 'win32')).toBe(`& '${windows}' run -- x`);
  });
});
