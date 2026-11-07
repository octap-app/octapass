import { parseCsv, toCsv } from './csv';

describe('parseCsv', () => {
  it('splits rows and fields', () => {
    expect(parseCsv('a,b,c\r\n1,2,3\r\n')).toEqual([
      ['a', 'b', 'c'],
      ['1', '2', '3'],
    ]);
    expect(parseCsv('a,b\n1,2')).toEqual([
      ['a', 'b'],
      ['1', '2'],
    ]);
  });

  it('handles quotes, escaped quotes, commas and embedded newlines', () => {
    expect(parseCsv('"a,b","say ""hi""","line 1\r\nline 2"\n')).toEqual([['a,b', 'say "hi"', 'line 1\r\nline 2']]);
  });

  it('keeps empty fields and empty lines in the middle', () => {
    expect(parseCsv('a,,c\n\n,\n1')).toEqual([['a', '', 'c'], [''], ['', ''], ['1']]);
  });

  it('strips a BOM and drops empty trailing lines', () => {
    expect(parseCsv('﻿name\r\nx\r\n\r\n,\r\n')).toEqual([['name'], ['x']]);
    expect(parseCsv('')).toEqual([]);
  });

  it('keeps a quote in the middle of an unquoted field', () => {
    expect(parseCsv('5" screen,x')).toEqual([['5" screen', 'x']]);
  });
});

describe('toCsv', () => {
  it('quotes only where needed and ends rows with CRLF', () => {
    expect(toCsv([['a', 'b,c', 'd"e', 'f\ng', ' padded'], ['', 'x']])).toBe(
      'a,"b,c","d""e","f\ng"," padded"\r\n,x\r\n',
    );
  });

  it('leaves formula-like cells untouched', () => {
    expect(toCsv([['=1+1', '+x', '-y', '@z']])).toBe('=1+1,+x,-y,@z\r\n');
  });

  it('round-trips through parseCsv', () => {
    const rows = [
      ['title', 'password', 'notes'],
      ['Bank', 'p,"w"\'d', 'multi\r\nline'],
      ['', '=cmd', ' spaced '],
    ];
    expect(parseCsv(toCsv(rows))).toEqual(rows);
  });
});
