// The vault worker: the WASM crypto core, the session keys and the decrypted vault live here.
// The core (about 800 KB, 320 KB compressed) loads in the background after the page has rendered.
// The full core (with OpenPGP, strength estimates and image decoders) loads only to import a Proton
// Pass PGP-encrypted export, which the web core can't read. The tools build loads only when the
// Tools section is used, so signing in stays a small download.

import { startVaultWorker } from '@octapass/vault-client/remote/worker';
import wasmUrl from '@octapass/core/octapass_core_bg.wasm?url';

startVaultWorker(
  async () => {
    const core = await import('@octapass/core');
    await core.default({ module_or_path: wasmUrl });
    return core;
  },
  self as unknown as Parameters<typeof startVaultWorker>[1],
  async () => {
    const [full, { default: fullWasmUrl }] = await Promise.all([import('@octapass/core/full'), import('@octapass/core/full/octapass_core_bg.wasm?url')]);
    await full.default({ module_or_path: fullWasmUrl });
    return full;
  },
  async () => {
    const [tools, { default: toolsWasmUrl }] = await Promise.all([import('@octapass/core/tools'), import('@octapass/core/tools/octapass_core_bg.wasm?url')]);
    await tools.default({ module_or_path: toolsWasmUrl });
    return tools;
  },
);
