import { html, stubLayout } from '../test/layout';
import { coverProblem, visibilityProblem } from './visibility';

let restore: () => void;
beforeEach(() => (restore = stubLayout()));
afterEach(() => restore());

const input = (id: string) => document.getElementById(id) as HTMLInputElement;

describe('visibilityProblem', () => {
  it('accepts a plain visible field', () => {
    html('<input id="a">');
    expect(visibilityProblem(input('a'))).toBeNull();
  });

  it.each([
    ['<input id="a" type="hidden">', 'hidden'],
    ['<input id="a" style="visibility:hidden">', 'hidden'],
    ['<div style="display:none"><input id="a"></div>', 'hidden'],
    ['<input id="a" style="clip:rect(0px, 0px, 0px, 0px);position:absolute">', 'hidden'],
    ['<input id="a" style="clip-path:inset(50%)">', 'hidden'],
    ['<div style="opacity:0.5"><div style="opacity:0.5"><input id="a"></div></div>', 'transparent'],
    ['<input id="a" data-rect="0 0 1 1">', 'zero-size'],
    ['<input id="a" data-rect="-9999 0 200 30">', 'off-screen'],
    ['<input id="a" style="position:fixed" data-rect="2048 0 200 30">', 'off-screen'],
    ['<div style="position:fixed"><input id="a" data-rect="0 900 200 30"></div>', 'off-screen'],
    ['<input id="a" disabled>', 'not-editable'],
    ['<input id="a" readonly>', 'not-editable'],
  ])('%s → %s', (markup, problem) => {
    html(markup);
    expect(visibilityProblem(input('a'))).toBe(problem);
  });

  it('refuses a field placed beyond the end of the page, where scrolling never reaches', () => {
    html('<input id="a" data-rect="3000 0 200 30"><input id="b" data-rect="16 1500 200 30">');
    const page = document.documentElement;
    Object.defineProperty(page, 'scrollWidth', { configurable: true, value: 1024 });
    Object.defineProperty(page, 'scrollHeight', { configurable: true, value: 2000 });
    try {
      expect(visibilityProblem(input('a'))).toBe('off-screen');
      // Below the fold but inside the page: a long form the user can scroll to.
      expect(visibilityProblem(input('b'))).toBeNull();
    } finally {
      delete (page as unknown as Record<string, unknown>).scrollWidth;
      delete (page as unknown as Record<string, unknown>).scrollHeight;
    }
  });

  it('looks through shadow roots for hidden ancestors', () => {
    html('<div id="host" style="display:none"></div>');
    const root = document.getElementById('host')!.attachShadow({ mode: 'open' });
    root.innerHTML = '<input>';
    expect(visibilityProblem(root.querySelector('input')!)).toBe('hidden');
  });
});

describe('coverProblem', () => {
  it('accepts a field that is on top', () => {
    html('<input id="a" data-rect="0 0 200 30">');
    expect(coverProblem(input('a'))).toBeNull();
  });

  it('flags a field with something drawn over it', () => {
    html('<input id="a" data-rect="0 0 200 30"><div data-rect="0 0 300 300"></div>');
    expect(coverProblem(input('a'))).toBe('covered');
  });

  it('accepts its own label drawn over it and our own UI', () => {
    html('<input id="a" data-rect="0 0 200 30"><label for="a" data-rect="0 0 200 30">Email</label>');
    expect(coverProblem(input('a'))).toBeNull();
    html('<input id="a" data-rect="0 0 200 30"><div id="ours" data-rect="0 0 200 30"></div>');
    expect(coverProblem(input('a'), (top) => top.id === 'ours')).toBeNull();
  });

  it('tolerates a small overlap', () => {
    html('<input id="a" data-rect="0 0 200 30"><span data-rect="150 0 50 30"></span>');
    expect(coverProblem(input('a'))).toBeNull();
  });

  it('says when the field is out of view', () => {
    html('<input id="a" data-rect="0 5000 200 30">');
    expect(coverProblem(input('a'))).toBe('not-in-view');
  });
});
