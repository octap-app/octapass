import { dispatchTrusted, trustedClick } from '../test/trusted';
import { askUser, resetNotices, showToast, type Question } from './notice';

// The notices' shadow root is closed; keep a handle on it as it's made.
let roots: ShadowRoot[] = [];
const attach = HTMLElement.prototype.attachShadow;
beforeEach(() => {
  roots = [];
  vi.spyOn(HTMLElement.prototype, 'attachShadow').mockImplementation(function (this: HTMLElement, init: ShadowRootInit) {
    const root = attach.call(this, init);
    roots.push(root);
    return root;
  });
});
afterEach(() => {
  resetNotices();
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.body.replaceChildren();
});

const hosts = () => document.querySelectorAll('octapass-notice');
const cards = () => [...(roots.at(-1)?.querySelectorAll<HTMLElement>('.card') ?? [])];
const button = (label: string) => [...(roots.at(-1)?.querySelectorAll('button') ?? [])].find((b) => (b.textContent || b.getAttribute('aria-label')) === label)!;

const save: Question<'save' | 'notNow' | 'never'> = {
  title: 'Save this login?',
  host: 'example.com',
  rows: [
    { icon: 'user', text: 'maya@example.com' },
    { icon: 'key', text: 'Password', masked: true },
  ],
  primary: { value: 'save', label: 'Save' },
  secondary: { value: 'notNow', label: 'Not now' },
  quiet: { value: 'never', label: 'Never for this site' },
};

describe('save prompts', () => {
  it('shows the site, the username and a masked password, in a closed shadow root', () => {
    askUser(save, () => undefined);
    expect(hosts()).toHaveLength(1);
    expect(hosts()[0]!.shadowRoot).toBeNull();
    const [card] = cards();
    expect(card).toHaveAttribute('role', 'dialog');
    expect(card).toHaveAccessibleName('Save this login?');
    expect(card!.querySelector('.host')).toHaveTextContent('example.com');
    expect(card!.textContent).toContain('maya@example.com');
    // Never the password itself: the prompt doesn't have it.
    expect(card!.querySelector('[role="img"]')).toHaveAccessibleName('Password');
    // The primary answer last, "Never" first and quiet.
    expect([...card!.querySelectorAll('.actions button')].map((b) => [b.className, b.textContent])).toEqual([
      ['quiet', 'Never for this site'],
      ['btn secondary', 'Not now'],
      ['btn primary', 'Save'],
    ]);
  });

  it('answers only trusted clicks, and only once', () => {
    const onAnswer = vi.fn();
    askUser(save, onAnswer);
    button('Save').click();
    button('Save').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onAnswer).not.toHaveBeenCalled();
    trustedClick(button('Save'));
    expect(onAnswer).toHaveBeenCalledExactlyOnceWith('save', false);
    expect(hosts()).toHaveLength(0);
  });

  it('takes the close button and a trusted Escape as “Not now”', () => {
    const first = vi.fn();
    askUser(save, first);
    trustedClick(cards()[0]!.querySelector('.close')!);
    expect(first).toHaveBeenCalledWith('notNow', false);

    const second = vi.fn();
    askUser(save, second);
    cards()[0]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(second).not.toHaveBeenCalled();
    dispatchTrusted(cards()[0]!, new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(second).toHaveBeenCalledWith('notNow', false);
  });

  it('ignores a tick the page set', () => {
    const onAnswer = vi.fn();
    askUser({ ...save, check: 'Also save the security code' }, onAnswer);
    const box = roots.at(-1)!.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    box.checked = true;
    box.dispatchEvent(new Event('change'));
    expect(box.checked).toBe(false);
    trustedClick(button('Save'));
    expect(onAnswer).toHaveBeenCalledWith('save', false);

    askUser({ ...save, check: 'Also save the security code' }, onAnswer);
    const real = roots.at(-1)!.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    real.checked = true;
    dispatchTrusted(real, new Event('change'));
    trustedClick(button('Save'));
    expect(onAnswer).toHaveBeenLastCalledWith('save', true);
  });

  it('stacks several notices in one layer, and removes the layer with the last', () => {
    const takeBack = askUser(save, () => undefined);
    askUser({ ...save, title: 'Add this website to this login?' }, () => undefined);
    showToast('One-time code copied');
    expect(hosts()).toHaveLength(1);
    expect(roots).toHaveLength(1);
    // Newest first.
    expect(cards().map((c) => c.querySelector('.title')!.textContent)).toEqual(['One-time code copied', 'Add this website to this login?', 'Save this login?']);
    takeBack();
    expect(cards()).toHaveLength(2);
    trustedClick(button('Save'));
    expect(hosts()).toHaveLength(1);
    for (const close of roots[0]!.querySelectorAll<HTMLElement>('.close')) trustedClick(close);
    expect(hosts()).toHaveLength(0);
  });

  it('opens inside an open modal dialog, where the rest of the page is inert', () => {
    const dialog = document.createElement('dialog');
    document.body.append(dialog);
    const modal = vi.spyOn(document, 'querySelector').mockImplementation((selector: string) => (selector === 'dialog:modal' ? dialog : null));
    askUser(save, () => undefined);
    modal.mockRestore();
    expect(hosts()[0]!.parentElement).toBe(dialog);
  });

  it('parses its stylesheet once for every notice in the frame', () => {
    askUser(save, () => undefined);
    resetNotices();
    askUser(save, () => undefined);
    // jsdom has no adoptedStyleSheets: the <style> fallback.
    expect(roots.at(-1)!.querySelectorAll('style')).toHaveLength(1);
    expect(roots.at(-1)!.querySelector('style')!.textContent).toContain('--trust');
  });

  it('writes page data as text, never markup', () => {
    askUser({ ...save, host: '<img src=x onerror=alert(1)>', rows: [{ icon: 'user', text: '<b>maya</b>' }] }, () => undefined);
    expect(roots.at(-1)!.querySelector('img, b')).toBeNull();
  });
});

describe('toasts', () => {
  it('go away by themselves, and wait while hovered', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    showToast('One-time code copied', 'Paste it into the page.', { ms: 4000, dismiss: 'Dismiss' });
    expect(cards()[0]).toHaveAttribute('role', 'status');
    vi.advanceTimersByTime(1000);
    cards()[0]!.dispatchEvent(new Event('pointerenter'));
    vi.advanceTimersByTime(10_000);
    expect(hosts()).toHaveLength(1);
    cards()[0]!.dispatchEvent(new Event('pointerleave'));
    vi.advanceTimersByTime(2900);
    expect(hosts()).toHaveLength(1);
    vi.advanceTimersByTime(200);
    expect(hosts()).toHaveLength(0);
  });

  it('with `stay`, wait to be closed, with no bar', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const close = showToast('Saved in Octa Pass', 'Marked “Unconfirmed” until you finish signing up.', { dismiss: 'Dismiss', stay: true });
    vi.advanceTimersByTime(60_000);
    expect(hosts()).toHaveLength(1);
    expect(cards()[0]!.querySelector('.progress')).toBeNull();
    close();
    expect(hosts()).toHaveLength(0);
  });

  it('keep at most three, pushing the oldest out', () => {
    for (const title of ['one', 'two', 'three', 'four']) showToast(title);
    expect(cards().map((c) => c.querySelector('.title')!.textContent)).toEqual(['four', 'three', 'two']);
  });

  it('close with a trusted click on the close button', () => {
    const close = showToast('Saved in Octa Pass', undefined, { dismiss: 'Dismiss' });
    button('Dismiss').click();
    expect(hosts()).toHaveLength(1);
    trustedClick(button('Dismiss'));
    expect(hosts()).toHaveLength(0);
    // Closing again is harmless.
    close();
  });
});
