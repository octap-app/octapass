import { Button, Segmented, Select, TextArea, TextField } from '@octapass/ui';
import { useState } from 'react';
import { t, type MessageKey } from '../../i18n';
import { Card, Output, ToolError, toolError, useTool } from './shared';
import styles from './Tools.module.css';

interface Claim {
  name: string;
  value: unknown;
  secondsFromNow?: number;
}

export interface Decoded {
  kind: 'jws' | 'jwe';
  header: unknown;
  algorithm?: string;
  payload?: unknown;
  payloadText?: string;
  claims: Claim[];
  warnings: string[];
}

type Unit = 'seconds' | 'minutes' | 'hours' | 'days';

function span(seconds: number): { count: number; unit: Unit } {
  if (seconds < 120) return { count: seconds, unit: 'seconds' };
  if (seconds < 7_200) return { count: Math.floor(seconds / 60), unit: 'minutes' };
  if (seconds < 172_800) return { count: Math.floor(seconds / 3_600), unit: 'hours' };
  return { count: Math.floor(seconds / 86_400), unit: 'days' };
}

function duration(seconds: number): string {
  const { count, unit } = span(Math.abs(seconds));
  return t(`tools.jwt.units.${unit}` as MessageKey, { count });
}

/** A claim in plain language: "Expires in 12 minutes", "Issued by acme". */
function claimText(claim: Claim): string {
  const seconds = claim.secondsFromNow;
  const value = typeof claim.value === 'string' ? claim.value : JSON.stringify(claim.value);
  switch (claim.name) {
    case 'iss':
      return t('tools.jwt.claims.iss', { value });
    case 'sub':
      return t('tools.jwt.claims.sub', { value });
    case 'aud':
      return t('tools.jwt.claims.aud', { value });
    case 'jti':
      return t('tools.jwt.claims.jti', { value });
    case 'exp':
      return seconds === undefined ? value : t(seconds > 0 ? 'tools.jwt.claims.expiresIn' : 'tools.jwt.claims.expiredAgo', { time: duration(seconds) });
    case 'nbf':
      return seconds === undefined ? value : t(seconds > 0 ? 'tools.jwt.claims.validIn' : 'tools.jwt.claims.validSince', { time: duration(seconds) });
    case 'iat':
      return seconds === undefined ? value : t(seconds > 0 ? 'tools.jwt.claims.issuedIn' : 'tools.jwt.claims.issuedAgo', { time: duration(seconds) });
    default:
      return value;
  }
}

/** What a token says. Shared with the extension popup. */
export function TokenView({ decoded }: { decoded: Decoded }) {
  return (
    <>
      {decoded.warnings.map((warning) => (
        <p key={warning} className={styles.bad}>
          {t(`tools.jwt.warnings.${warning}` as MessageKey)}
        </p>
      ))}
      {decoded.claims.length > 0 && (
        <ul className={styles.list}>
          {decoded.claims.map((claim) => (
            <li key={claim.name}>
              <bdi>{claimText(claim)}</bdi>
            </li>
          ))}
        </ul>
      )}
      <Output label={t('tools.jwt.header')} value={JSON.stringify(decoded.header, null, 2)} />
      {decoded.payload !== undefined ? (
        <Output label={t('tools.jwt.payload')} value={JSON.stringify(decoded.payload, null, 2)} />
      ) : decoded.payloadText ? (
        <Output label={t('tools.jwt.payload')} value={decoded.payloadText} />
      ) : (
        <p className={styles.note}>{t('tools.jwt.encrypted')}</p>
      )}
      <p className={styles.note}>{t('tools.jwt.unverified')}</p>
    </>
  );
}

/** Decode only, for the popup: `verify` and `sign` need keys, which stay out of it. */
export function JwtDecoder() {
  const { run, error } = useTool();
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState<Decoded>();

  async function read(text: string) {
    setToken(text);
    setDecoded(text.trim() ? await run<Decoded>('jwt.decode', { token: text }) : undefined);
  }

  return (
    <>
      <TextArea label={t('tools.jwt.token')} mono dir="ltr" spellCheck={false} value={token} onChange={(e) => void read(e.target.value)} />
      {token.trim() && <ToolError message={error} />}
      {decoded && <TokenView decoded={decoded} />}
    </>
  );
}

const SIGN_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
const isHmac = (algorithm: string) => algorithm.startsWith('HS');

interface Verified {
  valid: boolean;
  signatureValid: boolean;
  expired: boolean;
  notYetValid: boolean;
}

function VerifyCard() {
  const { toolkit, run, busy, error, setError } = useTool();
  const [token, setToken] = useState('');
  const [key, setKey] = useState('');
  const [secret, setSecret] = useState('');
  const [url, setUrl] = useState('');
  const [fetching, setFetching] = useState(false);
  const [result, setResult] = useState<Verified>();

  async function verify() {
    let keyText = key;
    if (url.trim()) {
      setFetching(true);
      try {
        keyText = await toolkit.fetchJwks!(url.trim());
      } catch (e) {
        setError(toolError(e));
        return;
      } finally {
        setFetching(false);
      }
    }
    setResult(await run<Verified>('jwt.verify', { token, key: keyText || undefined, secret: secret ? { value: secret } : undefined }));
  }

  const message = !result ? undefined : result.valid ? 'valid' : !result.signatureValid ? 'badSignature' : result.expired ? 'expired' : 'notYet';
  return (
    <Card title={t('tools.jwt.verify')}>
      <TextArea label={t('tools.jwt.token')} mono dir="ltr" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} />
      <TextArea label={t('tools.jwt.key')} hint={t('tools.jwt.keyHint')} mono dir="ltr" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} />
      <TextField label={t('tools.jwt.secret')} type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
      {toolkit.fetchJwks && <TextField label={t('tools.jwt.jwksUrl')} hint={t('tools.jwt.jwksHint')} dir="ltr" value={url} onChange={(e) => setUrl(e.target.value)} />}
      <div className={styles.actions}>
        <Button busy={busy || fetching} disabled={!token} onClick={() => void verify()}>
          {t('tools.jwt.verifyAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {message && <p className={result?.valid ? styles.ok : styles.bad}>{t(`tools.jwt.results.${message}` as MessageKey)}</p>}
    </Card>
  );
}

function SignCard() {
  const { run, busy, error, setError } = useTool();
  const [algorithm, setAlgorithm] = useState('ES256');
  const [claims, setClaims] = useState('{\n  "sub": "1234"\n}');
  const [key, setKey] = useState('');
  const [expires, setExpires] = useState('3600');
  const [token, setToken] = useState<string>();
  const [short, setShort] = useState(false);

  async function sign() {
    let payload: unknown;
    try {
      payload = JSON.parse(claims);
    } catch {
      setError(t('tools.jwt.badClaims'));
      return;
    }
    const seconds = Number.parseInt(expires, 10);
    const signed = await run<{ token: string; warnings: string[] }>('jwt.sign', {
      payload,
      algorithm,
      ...(isHmac(algorithm) ? { secret: { value: key } } : { key }),
      issuedNow: true,
      ...(Number.isNaN(seconds) ? {} : { expiresInSeconds: seconds }),
    });
    setToken(signed?.token);
    setShort(signed?.warnings.includes('shortSecret') ?? false);
  }

  return (
    <Card title={t('tools.jwt.sign')}>
      <div className={styles.row}>
        <Select label={t('tools.jwt.algorithm')} value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} options={SIGN_ALGORITHMS.map((value) => ({ value, label: value }))} />
        <TextField label={t('tools.jwt.expires')} inputMode="numeric" value={expires} onChange={(e) => setExpires(e.target.value)} />
      </div>
      <TextArea label={t('tools.jwt.claimsInput')} mono dir="ltr" spellCheck={false} value={claims} onChange={(e) => setClaims(e.target.value)} />
      <TextArea label={isHmac(algorithm) ? t('tools.jwt.secret') : t('tools.jwt.privateKey')} mono dir="ltr" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} />
      <div className={styles.actions}>
        <Button busy={busy} disabled={!key} onClick={() => void sign()}>
          {t('tools.jwt.signAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {short && <p className={styles.bad}>{t('tools.jwt.shortSecret')}</p>}
      {token && <Output label={t('tools.jwt.token')} value={token} />}
    </Card>
  );
}

function DecryptCard() {
  const { run, busy, error } = useTool();
  const [token, setToken] = useState('');
  const [key, setKey] = useState('');
  const [secret, setSecret] = useState('');
  const [plain, setPlain] = useState<string>();

  async function decrypt() {
    const opened = await run<{ text?: string; base64url: string }>('jwt.decrypt', { token, key: key || undefined, secret: secret ? { value: secret } : undefined });
    setPlain(opened ? (opened.text ?? opened.base64url) : undefined);
  }

  return (
    <Card title={t('tools.jwt.decrypt')}>
      <TextArea label={t('tools.jwt.token')} mono dir="ltr" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} />
      <TextArea label={t('tools.jwt.key')} mono dir="ltr" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} />
      <TextField label={t('tools.jwt.secret')} hint={t('tools.jwt.secretHint')} type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
      <div className={styles.actions}>
        <Button busy={busy} disabled={!token} onClick={() => void decrypt()}>
          {t('tools.jwt.decryptAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {plain !== undefined && <Output label={t('tools.jwt.plaintext')} value={plain} gated />}
    </Card>
  );
}

type Mode = 'read' | 'verify' | 'sign' | 'decrypt';

export function JwtPanel() {
  const [mode, setMode] = useState<Mode>('read');
  return (
    <div className={styles.panel}>
      <Segmented
        label={t('tools.panels.jwt')}
        value={mode}
        onChange={setMode}
        block
        options={[
          { value: 'read', label: t('tools.jwt.read') },
          { value: 'verify', label: t('tools.jwt.verify') },
          { value: 'sign', label: t('tools.jwt.sign') },
          { value: 'decrypt', label: t('tools.jwt.decrypt') },
        ]}
      />
      {mode === 'read' && (
        <Card>
          <JwtDecoder />
        </Card>
      )}
      {mode === 'verify' && <VerifyCard />}
      {mode === 'sign' && <SignCard />}
      {mode === 'decrypt' && <DecryptCard />}
    </div>
  );
}
