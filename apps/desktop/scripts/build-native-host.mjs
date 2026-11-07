// Builds octapass-native-host and puts it where the bundle picks it up (src-tauri/binaries), so
// it ships next to the app's own executable. Runs before `cargo tauri build` (Windows and Linux).
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const exe = process.platform === 'win32' ? '.exe' : '';

execFileSync('cargo', ['build', '--release', '-p', 'octapass-native-host'], { cwd: root, stdio: 'inherit' });
mkdirSync(new URL('../src-tauri/binaries/', import.meta.url), { recursive: true });
copyFileSync(
  new URL(`../target/release/octapass-native-host${exe}`, import.meta.url),
  new URL(`../src-tauri/binaries/octapass-native-host${exe}`, import.meta.url),
);
