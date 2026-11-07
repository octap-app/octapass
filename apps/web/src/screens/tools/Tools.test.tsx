import { screen } from '@testing-library/react';
import type { ToolkitService, VaultService } from '@octapass/vault-client';
import { vi } from 'vitest';
import { createSignedInService, renderApp } from '../../test/renderApp';

function withToolkit<T extends VaultService>(service: T, run: ToolkitService['run']): T {
  Object.defineProperty(service, 'toolkit', { value: { run } satisfies ToolkitService, configurable: true });
  return service;
}

describe('developer tools', { timeout: 30_000 }, () => {
  it('explains a token in plain language and says it isn’t verified', async () => {
    const run = vi.fn(async () => ({
      kind: 'jws',
      header: { alg: 'none' },
      algorithm: 'none',
      payload: { iss: 'acme' },
      claims: [
        { name: 'iss', value: 'acme' },
        { name: 'exp', value: 1, secondsFromNow: 720 },
      ],
      warnings: ['algNone'],
    }));
    const service = withToolkit(await createSignedInService(), run as unknown as ToolkitService['run']);
    const { user } = renderApp(service, '/tools');
    await user.selectOptions(await screen.findByRole('combobox', { name: 'Tool' }), 'JWT, JWS and JWE');
    await user.click(screen.getByRole('textbox', { name: 'Token' }));
    await user.paste('a.b.c');
    expect(await screen.findByText('Expires in 12 minutes')).toBeInTheDocument();
    expect(screen.getByText('Issued by acme')).toBeInTheDocument();
    expect(screen.getByText(/this token has no signature/)).toBeInTheDocument();
    expect(screen.getByText(/not that it’s genuine/)).toBeInTheDocument();
    expect(run).toHaveBeenCalledWith('jwt.decode', { token: 'a.b.c' });
  });

  it('hides a generated private key until it’s asked for, and offers saving', async () => {
    const run = vi.fn(async (op: string) => {
      if (op === 'cert.selfSigned') {
        return {
          certificate: 'CERT PEM',
          privateKey: 'SECRET KEY PEM',
          info: { subject: 'CN=localhost', issuer: 'CN=localhost', commonName: 'localhost', notAfter: 2_000_000_000, daysLeft: 365, sans: [], keyType: 'ec', keyBits: 256, curve: 'P-256', signatureAlgorithm: 'ecdsa', isCa: false, sha256: 'AA:BB', spkiSha256: 'aa', problems: [] },
        };
      }
      return { overview: {}, details: {} };
    });
    const service = withToolkit(await createSignedInService(), run as unknown as ToolkitService['run']);
    const { user } = renderApp(service, '/tools');
    await user.click(await screen.findByRole('button', { name: 'Make it' }));
    expect(await screen.findByText('CERT PEM')).toBeInTheDocument();
    expect(screen.queryByText('SECRET KEY PEM')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save to vault' })).toBeInTheDocument();
  });

  it('turns a tool’s error into a sentence', async () => {
    const { VaultError } = await import('@octapass/vault-client');
    const run = vi.fn(async () => {
      throw new VaultError('toolFailed', 'name_not_permitted');
    });
    const service = withToolkit(await createSignedInService(), run as unknown as ToolkitService['run']);
    const { user } = renderApp(service, '/tools');
    await user.click(await screen.findByRole('button', { name: 'Make it' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('limited to private names');
  });
});
