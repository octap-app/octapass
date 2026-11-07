import {
  EnvironmentError,
  diffEnvironments,
  isProductionStage,
  layerEnvironments,
  mergeVariables,
  parseDotenv,
  validEnvironmentKey,
  validateEnvironment,
  variablesFromDotenv,
  writeEnvironment,
} from './environment';
import type { EnvironmentVariable } from './types';

const pairs = (text: string) => parseDotenv(text).map(({ key, value }) => [key, value]);

const variable = (key: string, value: string, concealed = true): EnvironmentVariable => ({ key, value, concealed });

describe('parseDotenv', () => {
  it('reads the usual lines, export, comments and quoted values', () => {
    expect(
      pairs(`# database
DATABASE_PASSWORD=octapass://Work/Postgres/password
export STRIPE_KEY = octapass://Work/Stripe/api key   # the live key
GREETING="hello \\"world\\"\\n"
RAW='a # not a comment'
EMPTY=
`),
    ).toEqual([
      ['DATABASE_PASSWORD', 'octapass://Work/Postgres/password'],
      ['STRIPE_KEY', 'octapass://Work/Stripe/api key'],
      ['GREETING', 'hello "world"\n'],
      ['RAW', 'a # not a comment'],
      ['EMPTY', ''],
    ]);
  });

  it('keeps equals signs, hashes and quotes inside values', () => {
    expect(pairs('URL=postgres://u:p@db/app?sslmode=require&a=b\nTOKEN=abc==\nCOLOR=#ff0000\nTAG=a#b # comment\nQUOTE=it\'s\n')).toEqual([
      ['URL', 'postgres://u:p@db/app?sslmode=require&a=b'],
      ['TOKEN', 'abc=='],
      ['COLOR', '#ff0000'],
      ['TAG', 'a#b'],
      ['QUOTE', "it's"],
    ]);
  });

  it('reads multi-line double-quoted values', () => {
    const variables = parseDotenv('KEY="-----BEGIN PRIVATE KEY-----\n  abc\n-----END PRIVATE KEY-----" # the key\nNEXT=1\n');
    expect(variables[0]).toEqual({ key: 'KEY', value: '-----BEGIN PRIVATE KEY-----\n  abc\n-----END PRIVATE KEY-----', line: 1 });
    expect(variables[1]).toMatchObject({ key: 'NEXT', line: 4 });
  });

  it('says which line is wrong, without the value', () => {
    expect(() => parseDotenv('A=1\nnot a line\n')).toThrow('line 2: expected KEY=value');
    expect(() => parseDotenv('1A=x')).toThrow('line 1: names are letters');
    expect(() => parseDotenv("A='x")).toThrow("line 1 (A): a quote isn't closed");
    expect(() => parseDotenv('A="x" y')).toThrow('line 1 (A): unexpected text after the closing quote');
    expect(() => parseDotenv('A=secret\nnot a line\n')).toThrow(/line 2: expected/);
  });

  it('rejects duplicate names when building an environment, not when reading a file', () => {
    expect(parseDotenv('A=1\nA=2\n')).toHaveLength(2);
    expect(() => variablesFromDotenv('A=1\n\nA=2\n')).toThrow('line 3 (A): this name is already used');
    expect(variablesFromDotenv('A=1\nB=2\n').every((one) => one.concealed)).toBe(true);
  });
});

describe('validation', () => {
  it('accepts letters, digits and _, not starting with a digit', () => {
    for (const good of ['A', '_', 'a_b', '_1', 'PATH2']) expect(validEnvironmentKey(good)).toBe(true);
    for (const bad of ['', '1A', 'A-B', 'A B', 'É', 'A.B']) expect(validEnvironmentKey(bad)).toBe(false);
  });

  it('checks a whole environment', () => {
    expect(() => validateEnvironment({ variables: [variable('A', '1')] })).not.toThrow();
    expect(() => validateEnvironment({ variables: [variable('A', '1'), variable('A', '2')] })).toThrow('this name is already used');
    expect(() => validateEnvironment({ project: 'shop api', variables: [] })).toThrow('a project is up to 64');
    expect(() => validateEnvironment({ stage: 'qa:eu', variables: [] })).toThrow('a stage is up to 32');
  });

  it('knows production', () => {
    expect(isProductionStage('Production')).toBe(true);
    expect(isProductionStage('prod')).toBe(true);
    expect(isProductionStage('staging')).toBe(false);
    expect(isProductionStage(undefined)).toBe(false);
  });
});

const TRICKY: [string, string][] = [
  ['PLAIN', 'abc123'],
  ['URL', 'https://example.com/a?b=c&d=e'],
  ['EMPTY', ''],
  ['SPACES', '  padded  '],
  ['HASH', 'a #b'],
  ['SINGLE', "it's"],
  ['DOUBLE', 'say "hi"'],
  ['BOTH', 'it\'s "x" \\ back'],
  ['DOLLAR', '$HOME and ${PATH}'],
  ['MULTI', 'line 1\nline 2\n'],
  ['TAB', 'a\tb'],
];

describe('writeEnvironment', () => {
  it('round-trips dotenv', () => {
    const text = writeEnvironment(
      TRICKY.map(([key, value]) => ({ key, value })),
      'dotenv',
    );
    expect(pairs(text)).toEqual(TRICKY);
  });

  it('writes JSON in order', () => {
    expect(writeEnvironment([{ key: 'B', value: '1' }, { key: 'A', value: 'x"y\n' }], 'json')).toBe('{\n  "B": "1",\n  "A": "x\\"y\\n"\n}\n');
    expect(writeEnvironment([], 'json')).toBe('{}\n');
  });

  it('quotes for shells', () => {
    expect(writeEnvironment([{ key: 'A', value: "it's $HOME" }], 'shell')).toBe("export A='it'\\''s $HOME'\n");
    expect(writeEnvironment([{ key: 'A', value: "it's" }], 'powershell')).toBe("$env:A = 'it''s'\n");
  });

  it('writes docker lines and refuses line breaks', () => {
    expect(writeEnvironment([{ key: 'A', value: 'raw # here' }], 'docker')).toBe('A=raw # here\n');
    expect(() => writeEnvironment([{ key: 'KEY', value: 'a\nb' }], 'docker')).toThrow(EnvironmentError);
  });

  it('refuses invalid names', () => {
    expect(() => writeEnvironment([{ key: 'BAD-KEY', value: 'v' }], 'dotenv')).toThrow(EnvironmentError);
  });
});

describe('merging and diffing stages', () => {
  it('lets the stage override the shared set and later environments win', () => {
    const shared = [variable('LOG', 'info'), variable('DB', 'shared'), variable('REGION', 'eu')];
    const production = [variable('DB', 'prod'), variable('SENTRY', 'on')];
    expect(layerEnvironments([shared, production, [variable('LOG', 'debug')]]).map(({ key, value }) => [key, value])).toEqual([
      ['LOG', 'debug'],
      ['DB', 'prod'],
      ['REGION', 'eu'],
      ['SENTRY', 'on'],
    ]);
  });

  it('adds or replaces by name, keeping order and the old flags', () => {
    const current = [variable('A', '1', false), variable('B', '2')];
    expect(mergeVariables(current, [variable('C', '3'), variable('A', '9')])).toEqual([variable('A', '9', false), variable('B', '2'), variable('C', '3')]);
  });

  it('lists names missing or different without values', () => {
    const staging = [variable('A', '1'), variable('B', '2'), variable('ONLY_STAGING', 'x')];
    const production = [variable('B', '3'), variable('A', '1'), variable('ONLY_PROD', 'y')];
    expect(diffEnvironments(staging, production)).toEqual([
      { key: 'B', kind: 'different' },
      { key: 'ONLY_STAGING', kind: 'onlyInFirst' },
      { key: 'ONLY_PROD', kind: 'onlyInSecond' },
    ]);
    expect(diffEnvironments(staging, staging)).toEqual([]);
  });
});
