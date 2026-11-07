import { memoryStore } from '../test/memoryStore';
import { testCore } from '../test/core';
import { FrameApprovals } from './frames';
import { Matcher } from './matching';
import type { PageSender } from './senders';

const frame = (url: string, top: string | undefined, frameId = 3): PageSender => ({ tabId: 1, frameId, url, origin: new URL(url).origin, topOrigin: top && new URL(top).origin });
const idp = frame('https://accounts.idp.example/embed/signin', 'https://shop.example/checkout');

function setup() {
  const store = memoryStore();
  return { store, frames: new FrameApprovals(store, new Matcher(testCore), () => Date.parse('2026-10-24T09:00:00Z')) };
}

describe('FrameApprovals', () => {
  it('allows top frames and frames from the page’s own site', async () => {
    const { frames } = setup();
    expect(await frames.check(frame('https://evil.example/', 'https://evil.example/', 0))).toEqual({ allowed: true });
    expect(await frames.check(frame('https://login.shop.example/frame', 'https://www.shop.example/'))).toEqual({ allowed: true });
    expect(await frames.check(frame('https://account.bbc.co.uk/', 'https://www.bbc.co.uk/'))).toEqual({ allowed: true });
  });

  it('asks for a frame from another site, naming the frame’s host and the page’s site', async () => {
    const { frames } = setup();
    expect(await frames.check(idp)).toEqual({ allowed: false, ask: { frameHost: 'accounts.idp.example', site: 'shop.example' } });
    // Sites under a public suffix are separate sites.
    expect(await frames.check(frame('https://mallory.github.io/', 'https://alice.github.io/'))).toMatchObject({ allowed: false, ask: { site: 'alice.github.io' } });
    expect(await frames.check(frame('http://idp.test:8443/', 'http://localhost:3000/'))).toEqual({ allowed: false, ask: { frameHost: 'idp.test:8443', site: 'localhost:3000' } });
  });

  it('gives a frame nothing when the browser doesn’t say what page it’s in', async () => {
    const { frames } = setup();
    expect(await frames.check(frame('https://accounts.idp.example/', undefined))).toEqual({ allowed: false });
    expect(await frames.approve(frame('https://accounts.idp.example/', undefined))).toBe(false);
  });

  it('remembers an approval for that frame origin on that site only, until it’s removed', async () => {
    const { frames, store } = setup();
    expect(await frames.approve(idp)).toBe(true);
    expect(await frames.check(idp)).toEqual({ allowed: true });
    expect(await frames.check(frame('https://accounts.idp.example/other', 'https://www.shop.example/'))).toEqual({ allowed: true });
    // Another site embedding the same frame, or another origin of the frame's site, asks again.
    expect(await frames.check(frame('https://accounts.idp.example/embed/signin', 'https://other.example/'))).toMatchObject({ allowed: false });
    expect(await frames.check(frame('https://login.idp.example/', 'https://shop.example/'))).toMatchObject({ allowed: false });
    expect(await frames.check(frame('http://accounts.idp.example/', 'https://shop.example/'))).toMatchObject({ allowed: false });

    // Approving twice keeps one entry.
    await frames.approve(idp);
    expect(await frames.list()).toEqual([{ site: 'shop.example', origin: 'https://accounts.idp.example', approvedAt: '2026-10-24T09:00:00.000Z' }]);
    expect(store.data.size).toBe(1);

    await frames.remove('shop.example', 'https://accounts.idp.example');
    expect(await frames.list()).toEqual([]);
    expect(await frames.check(idp)).toMatchObject({ allowed: false });
  });
});
