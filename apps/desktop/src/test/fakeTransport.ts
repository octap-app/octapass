import type { Transport } from '../transport';

type Handler = (args: Record<string, unknown> | undefined) => unknown;

/** Commands answered by handlers, and events the test pushes. */
export class FakeTransport implements Transport {
  readonly calls: { command: string; args?: Record<string, unknown> }[] = [];
  private readonly handlers = new Map<string, Handler>();
  private readonly listeners = new Map<string, Set<(payload: never) => void>>();

  on(command: string, handler: Handler): this {
    this.handlers.set(command, handler);
    return this;
  }

  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push({ command, args });
    const handler = this.handlers.get(command);
    if (!handler) throw { code: 'unexpected', message: `no handler for ${command}` };
    return (await handler(args)) as T;
  }

  /** Raw bytes arrive in the handler as `{ bytes, headers }`. */
  invokeBytes<T>(command: string, bytes: Uint8Array, headers: Record<string, string>): Promise<T> {
    return this.invoke<T>(command, { bytes, headers });
  }

  async listen<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
    const set = this.listeners.get(event) ?? new Set();
    set.add(handler as (payload: never) => void);
    this.listeners.set(event, set);
    return () => set.delete(handler as (payload: never) => void);
  }

  emit(event: string, payload: unknown): void {
    for (const handler of this.listeners.get(event) ?? []) handler(payload as never);
  }
}
