import * as tools from './index';

describe('tools index', () => {
  it('exposes the public API of every tool module', () => {
    for (const name of [
      'randomBytes',
      'randomInt',
      'crockfordEncode',
      'crockfordDecode',
      'base32Decode',
      'bytesToHex',
      'generatePassword',
      'generatorEntropyBits',
      'estimateStrength',
      'parseTotp',
      'isValidTotp',
      'totpCode',
      'createBreachChecker',
      'hostnameOf',
      'registrableDomain',
      'buildHealthReport',
      'buildRecoveryMap',
      'parseCsv',
      'toCsv',
      'exportJson',
      'exportCsv',
      'parseImport',
    ]) {
      expect(tools).toHaveProperty(name, expect.any(Function));
    }
    expect(tools.PWNED_PASSWORDS_URL).toBe('https://api.pwnedpasswords.com');
    expect(tools.DEFAULT_PASSWORD_OPTIONS.kind).toBe('password');
    expect(tools.DEFAULT_PASSPHRASE_OPTIONS.kind).toBe('passphrase');
  });
});
