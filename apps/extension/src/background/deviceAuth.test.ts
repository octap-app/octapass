import { DEFAULT_DEVICE_AUTH_SETTINGS, type DeviceAuthSettings } from '@octapass/vault-client';
import { AutofillAuth } from './deviceAuth';

function setup(patch: Partial<DeviceAuthSettings> = {}, device = true, stayUnlocked = false) {
  const opens: string[] = [];
  const closed: number[] = [];
  let keepalive = 0;
  const auth = new AutofillAuth({
    canConfirmWithDevice: async () => device,
    openPrompt: async (id) => {
      opens.push(id);
      return 7;
    },
    closePrompt: (windowId) => void closed.push(windowId),
    busy: (waiting) => void (keepalive += waiting ? 1 : -1),
    settings: async () => ({ ...DEFAULT_DEVICE_AUTH_SETTINGS, ...patch }),
    stayUnlocked: () => stayUnlocked,
  });
  return { auth, opens, closed, pending: () => keepalive };
}

describe('AutofillAuth', () => {
  it('asks with the device check on every fill by default', async () => {
    const { auth, opens, pending } = setup();
    const answer = auth.request();
    await vi.waitFor(() => expect(opens).toHaveLength(1));
    expect(pending()).toBe(1);
    auth.answer(opens[0]!, true);
    expect(await answer).toBe(true);
    expect(pending()).toBe(0);
  });

  it('fills without asking while staying unlocked, whatever the greyed-out gate says (plan 18)', async () => {
    const { auth, opens } = setup({ requireDeviceAuthOnAutofill: true }, true, true);
    expect(await auth.request()).toBe(true);
    expect(opens).toEqual([]);
  });

  it('fills directly when its own gate is off, even with device auth available', async () => {
    const { auth, opens } = setup({ requireDeviceAuthOnAutofill: false });
    expect(await auth.request()).toBe(true);
    expect(opens).toEqual([]);
  });

  it('follows Google parity on a device with no device unlock, without opening a prompt', async () => {
    const { auth, opens } = setup({}, false);
    expect(await auth.request()).toBe(true);
    expect(opens).toEqual([]);
  });

  it('stops a fill when the user cancels, and closes the prompt', async () => {
    const { auth, opens, closed } = setup();
    const answer = auth.request();
    await vi.waitFor(() => expect(opens).toHaveLength(1));
    auth.answer(opens[0]!, false);
    expect(await answer).toBe(false);
    expect(closed).toEqual([7]);
  });

  it('stops a fill when its prompt window is closed', async () => {
    const { auth, opens } = setup();
    const answer = auth.request();
    await vi.waitFor(() => expect(opens).toHaveLength(1));
    auth.windowClosed(7);
    expect(await answer).toBe(false);
  });

  it('answers every waiting fill when the vault locks', async () => {
    const { auth, opens } = setup();
    const first = auth.request();
    const second = auth.request();
    await vi.waitFor(() => expect(opens).toHaveLength(2));
    auth.cancelAll();
    expect(await first).toBe(false);
    expect(await second).toBe(false);
  });

  describe('filling a card', () => {
    const answer = async (auth: AutofillAuth, opens: string[], approved: boolean) => {
      await vi.waitFor(() => expect(opens).toHaveLength(1));
      auth.answer(opens[0]!, approved);
    };

    it('fills without asking when no gate is on', async () => {
      const { auth, opens } = setup({ requireDeviceAuthOnAutofill: false });
      await expect(auth.requestCard(true)).resolves.toEqual({ fill: true, cvv: true });
      expect(opens).toEqual([]);
    });

    it('asks once for the security code when filling itself would not ask', async () => {
      const { auth, opens } = setup({ requireDeviceAuthOnAutofill: false, requireReauthForCvv: true });
      const filled = auth.requestCard(true);
      await answer(auth, opens, true);
      await expect(filled).resolves.toEqual({ fill: true, cvv: true });
    });

    it('still fills the card when the code alone is refused', async () => {
      const { auth, opens } = setup({ requireDeviceAuthOnAutofill: false, requireReauthForCvv: true });
      const filled = auth.requestCard(true);
      await answer(auth, opens, false);
      await expect(filled).resolves.toEqual({ fill: true, cvv: false });
    });

    it('fills nothing when the fill gate is refused, with one prompt for both', async () => {
      const { auth, opens } = setup({ requireReauthForCvv: true });
      const filled = auth.requestCard(true);
      await answer(auth, opens, false);
      await expect(filled).resolves.toEqual({ fill: false, cvv: false });
      expect(opens).toHaveLength(1);
    });

    it('asks on a device with no lock, where the master password answers', async () => {
      const { auth, opens } = setup({ requireReauthForCvv: true }, false);
      const filled = auth.requestCard(true);
      await answer(auth, opens, true);
      await expect(filled).resolves.toEqual({ fill: true, cvv: true });
    });

    it("doesn't ask for a card with no security code", async () => {
      const { auth, opens } = setup({ requireDeviceAuthOnAutofill: false, requireReauthForCvv: true });
      await expect(auth.requestCard(false)).resolves.toEqual({ fill: true, cvv: true });
      expect(opens).toEqual([]);
    });
  });
});
