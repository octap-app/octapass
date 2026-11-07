import type { SaveAnswer, SavePrompt, SaveResponse } from '../shared/messages';
import { apiKeyOffers, OFFER_MS } from './apiKeyOffer';

const value = 'FAKE-key-value';
const prompt: SavePrompt = { id: 'p1', kind: 'save', item: 'apiKey', host: 'dev.example', service: 'GitHub' };

function setup(response: SaveResponse = { prompt }) {
  const answers: unknown[][] = [];
  const shown: { answered: (answer: SaveAnswer) => void; close: ReturnType<typeof vi.fn> }[] = [];
  const offer = vi.fn(async (): Promise<SaveResponse> => response);
  const saved = vi.fn();
  const onPaste = apiKeyOffers({
    offer,
    show: (_prompt, answered) => {
      const close = vi.fn();
      shown.push({ answered, close });
      return close;
    },
    answer: async (...args) => {
      answers.push(args);
      return true;
    },
    saved,
  });
  return { onPaste, offer, shown, answers, saved };
}

describe('apiKeyOffers', () => {
  it('asks with the kind only, and sends the value only on Save', async () => {
    const { onPaste, offer, shown, answers, saved } = setup();
    await onPaste({ kind: 'github', value });
    expect(offer.mock.calls).toEqual([['github']]);
    expect(answers).toEqual([]);
    shown[0]!.answered('save');
    await Promise.resolve();
    await Promise.resolve();
    expect(answers).toEqual([['p1', 'save', value]]);
    expect(shown[0]!.close).toHaveBeenCalled();
    expect(saved).toHaveBeenCalledWith(true);
  });

  it.each(['notNow', 'never'] as const)('never sends the value on %s, and stops asking on this page', async (choice) => {
    const { onPaste, offer, shown, answers } = setup();
    await onPaste({ kind: 'github', value });
    shown[0]!.answered(choice);
    expect(answers).toEqual([['p1', choice]]);
    await onPaste({ kind: 'github', value });
    expect(offer).toHaveBeenCalledTimes(1);
  });

  it('shows nothing when the service worker says no', async () => {
    const { onPaste, shown } = setup(null);
    await onPaste({ kind: 'github', value });
    expect(shown).toEqual([]);
  });

  it('replaces the prompt when another key is pasted', async () => {
    const { onPaste, shown, answers } = setup();
    await onPaste({ kind: 'github', value });
    await onPaste({ kind: 'stripe', value: 'FAKE-second' });
    expect(shown[0]!.close).toHaveBeenCalled();
    shown[1]!.answered('save');
    expect(answers).toEqual([['p1', 'save', 'FAKE-second']]);
  });

  it('takes the prompt away when it isn’t answered', async () => {
    vi.useFakeTimers();
    const { onPaste, shown } = setup();
    await onPaste({ kind: 'github', value });
    vi.advanceTimersByTime(OFFER_MS);
    expect(shown[0]!.close).toHaveBeenCalled();
    vi.useRealTimers();
  });
});
