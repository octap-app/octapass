import { memoryStore } from '../test/memoryStore';
import { SESSION_CREDENTIAL, SessionKeeper, type Unlocker, type UnlockRecord } from './sessionKeeper';

const record = (credentialId: string): UnlockRecord => ({ accountId: 'acct', credentialId, deviceSalt: 'salt', wrappedAsk: 'ask', enabledAt: '', lastPasswordUnlockAt: '' });

/** An engine that wraps by storing a device-unlock record through the keeper's storage, as the real one does. */
function unlocker(keeper: SessionKeeper): Unlocker {
  return {
    wrap: async (credentialId) => keeper.storage.set('device-unlock:acct', record(credentialId)),
    unwrap: async () => undefined,
  };
}

// Plan 03 History, 2026-11-05: whether the user opened the session goes with its wrap, and nowhere else.
describe('the session keeper', () => {
  it('remembers that the user opened the session, in the wrap, until a lock clears it', async () => {
    const memory = memoryStore();
    const keeper = new SessionKeeper(memoryStore(), memory);
    await keeper.save(unlocker(keeper), true);
    expect(await keeper.read()).toMatchObject({ record: { credentialId: SESSION_CREDENTIAL }, confirmed: true });

    await keeper.clear();
    expect(await keeper.read()).toBeUndefined();
    expect([...memory.data.keys()]).toEqual([]);
  });

  it('says nothing of the kind for a session the user didn’t open', async () => {
    const keeper = new SessionKeeper(memoryStore(), memoryStore());
    await keeper.save(unlocker(keeper));
    const wrap = await keeper.read();
    expect(wrap).toBeDefined();
    expect(wrap?.confirmed).toBeUndefined();
  });
});
