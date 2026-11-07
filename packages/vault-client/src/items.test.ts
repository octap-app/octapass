import { emptyDraft, itemDates, keepAttachments, matchesFilter, restoredVersion, shareableSnapshot, summarizeItem, withAttachments, withPasswordHistory } from './items';
import type { Item, LoginDetails } from './types';

function login(overrides: Partial<LoginDetails> = {}, title = 'GitHub'): Item {
  return {
    id: 'a',
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    overview: { schemaVersion: 1, type: 'login', title, urls: ['https://github.com'], subtitle: 'maya', tags: ['work'] },
    details: { schemaVersion: 1, username: 'maya', password: 'old', ...overrides },
  };
}

describe('shareableSnapshot', () => {
  it('leaves out old passwords and the favourite flag, and keeps the rest', () => {
    const snapshot = shareableSnapshot({
      overview: { schemaVersion: 1, title: 'Bank', type: 'login', favorite: true, urls: ['https://bank.example'] },
      details: { schemaVersion: 1, username: 'maya', password: 'now', passwordHistory: [{ password: 'before', changedAt: '2026-01-01T00:00:00Z' }] },
    });
    expect(snapshot).toEqual({
      overview: { schemaVersion: 1, title: 'Bank', type: 'login', urls: ['https://bank.example'] },
      details: { schemaVersion: 1, username: 'maya', password: 'now' },
    });
  });
});

describe('attachments in details', () => {
  const file = { id: 'f1', name: 'scan.png', type: 'image/png', size: 10, key: 'wrapped' };

  it('share links leave them out: their files open only from the item', () => {
    const snapshot = shareableSnapshot({ overview: { schemaVersion: 1, title: 'Lease', type: 'document' }, details: { schemaVersion: 1, notes: 'n', attachments: [file] } });
    expect(snapshot.details).toEqual({ schemaVersion: 1, notes: 'n' });
  });

  it('edits keep the stored list, and new items start without one', () => {
    const stored = login({ attachments: [file] });
    const draft = { ...stored, details: { ...stored.details, attachments: [] } };
    expect(keepAttachments(draft, stored).details.attachments).toEqual([file]);
    expect(keepAttachments({ ...draft, details: { ...stored.details } }, undefined).details).not.toHaveProperty('attachments');
    expect(withAttachments(stored.details, [])).not.toHaveProperty('attachments');
  });
});

describe('summarizeItem', () => {
  it('flags one-time codes and passkeys without exposing secrets', () => {
    const summary = summarizeItem(login({ totp: 'JBSWY3DPEHPK3PXP', passkeys: [{ rpId: 'github.com', userName: 'maya', createdAt: '' }] }));
    expect(summary).toMatchObject({ hasTotp: true, hasPasskey: true, favorite: false });
    expect(JSON.stringify(summary)).not.toContain('old');
  });
});

describe('matchesFilter', () => {
  const summary = summarizeItem(login({}, 'Café Crème'));

  it('matches every search term against title, subtitle, URLs and tags, ignoring accents', () => {
    expect(matchesFilter(summary, { query: 'cafe github' })).toBe(true);
    expect(matchesFilter(summary, { query: 'WORK' })).toBe(true);
    expect(matchesFilter(summary, { query: 'old' })).toBe(false);
  });

  it('keeps trashed items out of normal lists', () => {
    const trashed = { ...summary, deletedAt: '2026-02-01T00:00:00.000Z' };
    expect(matchesFilter(trashed, {})).toBe(false);
    expect(matchesFilter(trashed, { trash: true })).toBe(true);
    expect(matchesFilter(summary, { trash: true })).toBe(false);
  });

  it('lists masked email provider tokens only when asked for by type', () => {
    const provider = { ...summary, type: 'maskedEmailProvider' as const };
    expect(matchesFilter(provider, {})).toBe(false);
    expect(matchesFilter(provider, { query: 'cafe' })).toBe(false);
    expect(matchesFilter(provider, { type: 'maskedEmailProvider' })).toBe(true);
    expect(matchesFilter(provider, { type: 'login' })).toBe(false);
  });

  it('lists only items with a one-time code when asked: logins with one, and a code saved on its own', () => {
    const withCode = summarizeItem(login({ totp: 'JBSWY3DPEHPK3PXP' }));
    const standalone = summarizeItem({ ...login({ totp: 'otpauth://totp/Example:maya?secret=JBSWY3DPEHPK3PXP', password: undefined }), overview: { schemaVersion: 1, type: 'password', title: 'Example code' } });
    expect(matchesFilter(withCode, { totp: true })).toBe(true);
    expect(matchesFilter(standalone, { totp: true })).toBe(true);
    expect(matchesFilter(summarizeItem(login()), { totp: true })).toBe(false);
    expect(matchesFilter({ ...withCode, deletedAt: '2026-02-01T00:00:00.000Z' }, { totp: true })).toBe(false);
    expect(matchesFilter(withCode, { totp: true, query: 'nothing like it' })).toBe(false);
  });
});

describe('withPasswordHistory', () => {
  const now = new Date('2026-03-01T00:00:00.000Z');

  it('records the old password when it changes', () => {
    const previous = login();
    const next = withPasswordHistory(previous, { ...previous, details: { ...(previous.details as LoginDetails), password: 'new' } }, now);
    expect((next.details as LoginDetails).passwordHistory).toEqual([{ password: 'old', changedAt: now.toISOString() }]);
  });

  it('leaves the draft alone when the password is unchanged', () => {
    const previous = login();
    const draft = { ...previous };
    expect(withPasswordHistory(previous, draft, now)).toBe(draft);
  });

  it('keeps the history an import already wrote', () => {
    const previous = login();
    const history = [{ password: 'old', changedAt: '2025-06-01T00:00:00Z' }];
    const next = withPasswordHistory(previous, { ...previous, details: { ...(previous.details as LoginDetails), password: 'new', passwordHistory: history } }, now);
    expect((next.details as LoginDetails).passwordHistory).toEqual(history);
  });

  it('drops the imported change date on an edit, unless the draft brings a new one', () => {
    const previous = { ...login(), overview: { ...login().overview, createdAt: '2020-01-01T00:00:00Z', updatedAt: '2021-01-01T00:00:00Z' } };
    const edited = withPasswordHistory(previous, { ...previous, overview: { ...previous.overview, title: 'Renamed' } }, now);
    expect(edited.overview.updatedAt).toBeUndefined();
    expect(edited.overview.createdAt).toBe('2020-01-01T00:00:00Z');
    const reimported = withPasswordHistory(previous, { ...previous, overview: { ...previous.overview, updatedAt: '2022-01-01T00:00:00Z' } }, now);
    expect(reimported.overview.updatedAt).toBe('2022-01-01T00:00:00Z');
  });
});

describe('itemDates', () => {
  it('prefers the imported dates and the latest password change', () => {
    const item = login({ passwordChangedAt: '2024-01-01T00:00:00Z', passwordHistory: [{ password: 'older', changedAt: '2025-01-01T00:00:00Z' }] });
    item.overview = { ...item.overview, createdAt: '2019-05-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z', lastUsedAt: '2025-02-01T00:00:00Z' };
    expect(itemDates(item)).toEqual({
      createdAt: '2019-05-01T00:00:00Z',
      updatedAt: '2025-01-01T00:00:00Z',
      lastUsedAt: '2025-02-01T00:00:00Z',
      passwordChangedAt: '2025-01-01T00:00:00Z',
    });
  });

  it('falls back to the sync record', () => {
    expect(itemDates(login())).toEqual({ createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', lastUsedAt: undefined, passwordChangedAt: undefined });
  });
});

describe('emptyDraft', () => {
  it('stamps the schema version on overview and details', () => {
    const draft = emptyDraft('secureNote', 'v1');
    expect(draft.overview.schemaVersion).toBe(1);
    expect(draft.details).toEqual({ schemaVersion: 1, notes: '' });
  });
});

describe('environment summaries', () => {
  const environment: Item = {
    id: 'env1',
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    overview: { schemaVersion: 1, type: 'environment', title: 'Shop API', subtitle: 'shop-api · production' },
    details: {
      schemaVersion: 1,
      project: 'shop-api',
      stage: 'production',
      variables: [
        { key: 'DATABASE_URL', value: 'postgres://secret', concealed: true },
        { key: 'PORT', value: '8080', concealed: false },
      ],
    },
  };

  it('carries the project, stage and variable names but never values', () => {
    const summary = summarizeItem(environment);
    expect(summary).toMatchObject({ project: 'shop-api', stage: 'production', variableKeys: ['DATABASE_URL', 'PORT'] });
    expect(JSON.stringify(summary)).not.toContain('postgres://secret');
  });

  it('is found by a variable name, never by a value', () => {
    const summary = summarizeItem(environment);
    expect(matchesFilter(summary, { query: 'database_url' })).toBe(true);
    expect(matchesFilter(summary, { query: 'postgres' })).toBe(false);
  });
});

describe('restoredVersion', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const hotp = (counter: number) => `otpauth://hotp/x?secret=${secret}&counter=${counter}`;
  const passkey = { rpId: 'github.com', userName: 'maya', createdAt: '2026-01-01T00:00:00.000Z' };
  const history = [{ password: 'older', changedAt: '2026-01-01T00:00:00.000Z' }];

  it('brings back what the item said, and nothing that lives outside a version', () => {
    const current = login({ password: 'new', totp: hotp(9), passkeys: [passkey], passwordHistory: history });
    current.overview.favorite = true;
    const old = login({ password: 'old', totp: hotp(3), notes: 'then' }, 'Old title');
    const draft = restoredVersion(current, old);
    expect(draft).toMatchObject({ id: 'a', vaultId: 'v1', revision: 1 });
    expect(draft.overview).toMatchObject({ title: 'Old title', favorite: true });
    const details = draft.details as LoginDetails;
    expect(details).toMatchObject({ password: 'old', notes: 'then', passkeys: [passkey], passwordHistory: history });
    expect(details.totp).toContain('counter=9');
  });

  it("doesn't move a favourite or a passkey back in", () => {
    const old = login({ passkeys: [passkey] });
    old.overview.favorite = true;
    const draft = restoredVersion(login(), old);
    expect(draft.overview.favorite).toBeUndefined();
    expect((draft.details as LoginDetails).passkeys).toBeUndefined();
  });
});

describe('summaries and hidden settings', () => {
  it('carry match modes for autofill and keep equivalent domains out of lists', () => {
    const item = login();
    item.overview.urlMatch = { 'https://github.com': 'host' };
    expect(summarizeItem(item).urlMatch).toEqual({ 'https://github.com': 'host' });
    const hidden = { ...summarizeItem(item), type: 'equivalentDomains' as const };
    expect(matchesFilter(hidden)).toBe(false);
    expect(matchesFilter(hidden, { type: 'equivalentDomains' })).toBe(true);
  });
});
