import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

/** How the web view talks to the app's Rust side: commands, and events it pushes. */
export interface Transport {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  /** A command whose argument is raw bytes (a file), with the rest in string headers. */
  invokeBytes<T>(command: string, bytes: Uint8Array, headers: Record<string, string>): Promise<T>;
  listen<T>(event: string, handler: (payload: T) => void): Promise<() => void>;
}

export function tauriTransport(): Transport {
  return {
    invoke: (command, args) => invoke(command, args),
    invokeBytes: (command, bytes, headers) => invoke(command, bytes, { headers }),
    listen: (event, handler) => listen(event, ({ payload }) => handler(payload as never)),
  };
}
