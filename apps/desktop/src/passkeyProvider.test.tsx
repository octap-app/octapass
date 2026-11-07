import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { setLocale } from '@octapass/web/src/i18n/core';
import { describe, expect, it, vi } from 'vitest';
import { desktopPasskeyProvider, withPasskeyProvider, type PasskeyProvider, type ProviderStatus } from './passkeyProvider';
import { PasskeyProviderSection } from './PasskeyProviderSection';
import { FakeTransport } from './test/fakeTransport';

const off: ProviderStatus = { available: true, registered: false, enabled: false };
const registered: ProviderStatus = { ...off, registered: true };
const on: ProviderStatus = { ...registered, enabled: true };

function provider(status: ProviderStatus, set: ProviderStatus | Error = registered): PasskeyProvider {
  return {
    status: vi.fn(async () => status),
    set: vi.fn(async () => {
      if (set instanceof Error) throw set;
      return set;
    }),
    openSettings: vi.fn(async () => {}),
  };
}

describe('the Windows passkey provider', () => {
  afterEach(() => setLocale('en'));

  it('is missing where the API or the package isn’t there', async () => {
    const transport = new FakeTransport().on('windows_passkey_status', () => ({ ...off, available: false }));
    expect(await desktopPasskeyProvider(transport)).toBeUndefined();
    expect(await desktopPasskeyProvider(new FakeTransport())).toBeUndefined();
  });

  it('drives the commands where it’s there', async () => {
    const transport = new FakeTransport().on('windows_passkey_status', () => off).on('windows_passkey_set', () => registered).on('windows_passkey_open_settings', () => undefined);
    const service = await desktopPasskeyProvider(transport);
    await expect(service?.set(true)).resolves.toEqual(registered);
    await service?.openSettings();
    expect(transport.calls.map((call) => call.command)).toEqual(['windows_passkey_status', 'windows_passkey_set', 'windows_passkey_open_settings']);
    expect(transport.calls[1]?.args).toEqual({ enabled: true });
  });

  it('is off by default, then asks for the step only Windows can take', async () => {
    const user = userEvent.setup();
    const service = provider(off);
    render(<PasskeyProviderSection provider={service} />);

    const toggle = await screen.findByRole('switch', { name: 'Use Octa Pass as a passkey provider' });
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    await user.click(toggle);

    expect(service.set).toHaveBeenCalledWith(true);
    await user.click(await screen.findByRole('button', { name: 'Open Windows Settings' }));
    expect(service.openSettings).toHaveBeenCalled();
  });

  it('says when Windows is using it, and turning it off asks Windows to remove it', async () => {
    const user = userEvent.setup();
    const service = provider(on, off);
    render(<PasskeyProviderSection provider={service} />);

    expect(await screen.findByText('Windows is using Octa Pass for passkeys.')).toBeInTheDocument();
    await user.click(screen.getByRole('switch'));
    expect(service.set).toHaveBeenCalledWith(false);
    expect(await screen.findByRole('switch')).toHaveAttribute('aria-checked', 'false');
  });

  it('keeps the switch where it was when Windows refuses', async () => {
    const user = userEvent.setup();
    render(<PasskeyProviderSection provider={provider(off, new Error('no'))} />);
    await user.click(await screen.findByRole('switch'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Windows didn’t accept the change.');
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false');
  });

  it('speaks Arabic', async () => {
    setLocale('ar');
    render(<PasskeyProviderSection provider={provider(off)} />);
    expect(await screen.findByRole('heading', { name: 'مفاتيح المرور في Windows' })).toBeInTheDocument();
  });

  it('adds its section to Settings only', () => {
    const settings = <div />;
    const routes = withPasskeyProvider([{ path: '/', children: [{ path: 'settings', element: settings }, { path: 'other', element: <div /> }] }], <span />);
    const children = routes[0]!.children!;
    expect((children[0]!.element as { props: { platformSection?: unknown } }).props.platformSection).toBeDefined();
    expect((children[1]!.element as { props: { platformSection?: unknown } }).props.platformSection).toBeUndefined();
  });
});
