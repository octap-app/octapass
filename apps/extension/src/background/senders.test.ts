import { isExtensionPage, pageSender } from './senders';

const ID = chrome.runtime.id;
const EXT = `chrome-extension://${ID}`;
const tab = { id: 7, url: 'https://shop.example.com/cart' } as chrome.tabs.Tab;

describe('isExtensionPage', () => {
  it('accepts our own pages', () => {
    expect(isExtensionPage({ id: ID, url: `${EXT}/app.html`, origin: EXT })).toBe(true);
    // The passkey prompt is framed by a website, so it has a tab.
    expect(isExtensionPage({ id: ID, url: `${EXT}/passkey.html#r1`, tab, frameId: 3 })).toBe(true);
  });

  it('refuses content scripts and other extensions', () => {
    expect(isExtensionPage({ id: ID, url: 'https://shop.example.com/', tab, frameId: 0 })).toBe(false);
    expect(isExtensionPage({ id: 'someone-else', url: `chrome-extension://someone-else/app.html` })).toBe(false);
    expect(isExtensionPage({ id: ID, url: `${EXT}.evil.com/app.html` })).toBe(false);
    expect(isExtensionPage({ id: ID, url: `${EXT}/app.html`, origin: 'https://evil.com' })).toBe(false);
  });
});

describe('pageSender', () => {
  it('describes the frame a content script runs in', () => {
    expect(pageSender({ id: ID, url: 'https://pay.example.net/frame', origin: 'https://pay.example.net', tab, frameId: 2 })).toEqual({
      tabId: 7,
      frameId: 2,
      url: 'https://pay.example.net/frame',
      origin: 'https://pay.example.net',
      topOrigin: 'https://shop.example.com',
    });
  });

  it('refuses anything that is not a web page in a tab', () => {
    expect(pageSender({ id: ID, url: `${EXT}/app.html` })).toBeUndefined();
    expect(pageSender({ id: ID, url: 'file:///etc/passwd', tab, frameId: 0 })).toBeUndefined();
    expect(pageSender({ id: ID, url: 'https://a.example.com/', tab })).toBeUndefined();
    expect(pageSender({ id: 'other', url: 'https://a.example.com/', tab, frameId: 0 })).toBeUndefined();
  });

  it('refuses a frame whose URL and origin disagree', () => {
    expect(pageSender({ id: ID, url: 'https://bank.example.com/', origin: 'https://evil.example.org', tab, frameId: 0 })).toBeUndefined();
  });
});
