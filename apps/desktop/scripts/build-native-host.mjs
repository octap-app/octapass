// Builds octapass-native-host and the CLI (octapass and its helpers) and puts them where the
// bundle picks them up (src-tauri/binaries), so they ship next to the app's own executable: the
// Linux packages install them in /usr/bin (tauri.conf.json). Runs before `cargo tauri build`
// (Windows and Linux). The CLI is in the repository's root workspace, not the desktop one.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const desktop = fileURLToPath(new URL('..', import.meta.url));
const repo = fileURLToPath(new URL('../../..', import.meta.url));
const exe = process.platform === 'win32' ? '.exe' : '';
const binaries = new URL('../src-tauri/binaries/', import.meta.url);

execFileSync('cargo', ['build', '--release', '-p', 'octapass-native-host'], { cwd: desktop, stdio: 'inherit' });
execFileSync('cargo', ['build', '--release', '-p', 'octapass-cli'], { cwd: repo, stdio: 'inherit' });
mkdirSync(binaries, { recursive: true });
copyFileSync(
  new URL(`../target/release/octapass-native-host${exe}`, import.meta.url),
  new URL(`octapass-native-host${exe}`, binaries),
);
for (const program of ['octapass', 'git-credential-octapass', 'octapass-git-sign', 'docker-credential-octapass']) {
  copyFileSync(new URL(`../../../target/release/${program}${exe}`, import.meta.url), new URL(`${program}${exe}`, binaries));
}
