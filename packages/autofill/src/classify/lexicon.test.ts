import { normalize } from '../dom/text';
import { match } from './lexicon';

const m = (concept: Parameters<typeof match>[0], text: string) => match(concept, normalize(text));

describe('match', () => {
  it('matches Latin keywords at word starts only', () => {
    expect(m('name', 'Last name')).toBe('name');
    expect(m('name', 'username')).toBeUndefined();
    expect(m('address-line2', 'Captcha')).toBeUndefined();
  });

  it('prefers the longest keyword', () => {
    expect(m('email', 'Email address of your account')).toBe('email address');
  });

  it('treats spaces in keywords as optional', () => {
    expect(m('username', 'username')).toBe('username');
    expect(m('username', 'user-name')).toBe('user-name');
  });

  it.each([
    ['password', 'Contraseña'],
    ['password', 'Mot de passe'],
    ['password', 'Passwort'],
    ['password', 'Senha'],
    ['password', 'Пароль'],
    ['password', '密码'],
    ['password', 'パスワード'],
    ['password', 'كلمة المرور'],
    ['password', 'पासवर्ड'],
    ['username', 'Nombre de usuario'],
    ['username', 'اسم المستخدم'],
    ['email', 'Correo electrónico'],
    ['confirm', 'Confirmar contraseña'],
    ['confirm', 'تأكيد كلمة المرور'],
    ['signup', 'إنشاء حساب'],
    ['login', 'Iniciar sesión'],
    ['one-time-code', 'رمز التحقق'],
    ['cc-number', 'Número de tarjeta'],
  ] as const)('knows %s in "%s"', (concept, text) => {
    expect(m(concept, text)).toBeTruthy();
  });
});
