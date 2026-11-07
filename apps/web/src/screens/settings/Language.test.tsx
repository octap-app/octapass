import { screen, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

function languages(list: string[]) {
  Object.defineProperty(navigator, 'languages', { value: list, configurable: true });
  window.dispatchEvent(new Event('languagechange'));
}

describe('language', { timeout: 30_000 }, () => {
  afterEach(() => languages(['en-US']));

  it('switches to Arabic, right to left, and back from Settings', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');
    const appearance = await screen.findByRole('region', { name: 'Appearance' });
    const language = within(appearance).getByRole('radiogroup', { name: 'Language' });
    expect(within(language).getByRole('radio', { name: 'System' })).toBeChecked();
    expect(document.documentElement).toHaveAttribute('dir', 'ltr');

    await user.click(within(language).getByRole('radio', { name: 'العربية' }));
    expect(await screen.findByRole('heading', { name: 'الإعدادات', level: 1 })).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('lang', 'ar');
    expect(document.documentElement).toHaveAttribute('dir', 'rtl');
    expect(JSON.parse(localStorage.getItem('octapass:settings')!)).toMatchObject({ language: 'ar' });
    // The vault's own names follow the language too.
    expect(screen.getAllByRole('link', { name: /الخزنة الشخصية/ }).length).toBeGreaterThan(0);

    const arabic = within(screen.getByRole('region', { name: 'المظهر' })).getByRole('radiogroup', { name: 'اللغة' });
    await user.click(within(arabic).getByRole('radio', { name: 'English' }));
    expect(await screen.findByRole('heading', { name: 'Settings', level: 1 })).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('dir', 'ltr');
  });

  it('follows the browser’s language until one is chosen', async () => {
    languages(['ar-EG', 'en']);
    const service = await createSignedInService();
    renderApp(service, '/items/all');
    expect(await screen.findByRole('heading', { name: 'كل العناصر', level: 1 })).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('dir', 'rtl');

    languages(['en-GB']);
    expect(await screen.findByRole('heading', { name: 'All items', level: 1 })).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('dir', 'ltr');
  });

  it('keeps passwords, codes and addresses left to right', async () => {
    languages(['ar']);
    const service = await createSignedInService();
    renderApp(service, '/items/all/new?type=login');
    expect(await screen.findByLabelText('كلمة المرور')).toHaveAttribute('dir', 'ltr');
    expect(screen.getByLabelText('الموقع الإلكتروني')).toHaveAttribute('dir', 'ltr');
    expect(screen.getByLabelText('رمز لمرة واحدة')).toHaveAttribute('dir', 'ltr');
    expect(screen.getByLabelText('العنوان')).not.toHaveAttribute('dir');
  });
});
