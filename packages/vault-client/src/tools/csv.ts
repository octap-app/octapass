/** RFC 4180, leniently: CRLF or LF line ends, a leading BOM, and stray text after a closing quote. */
export function parseCsv(text: string): string[][] {
  const input = text.startsWith('﻿') ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i]!;
    if (quoted) {
      if (char !== '"') field += char;
      else if (input[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (char === '"' && field === '') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && input[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  while (rows.length > 0 && rows.at(-1)!.every((cell) => cell === '')) rows.pop();
  return rows;
}

function quote(cell: string): string {
  return /[",\r\n]/.test(cell) || cell !== cell.trim() ? `"${cell.replaceAll('"', '""')}"` : cell;
}

/**
 * CRLF-terminated rows, quoting only where needed. Cells starting with = + - @ are written as they are:
 * the usual guard against spreadsheet formula injection (a leading ') would silently change passwords
 * when the file is imported again, and an export is meant to be read back by password managers.
 */
export function toCsv(rows: string[][]): string {
  return rows.map((row) => row.map(quote).join(',') + '\r\n').join('');
}
