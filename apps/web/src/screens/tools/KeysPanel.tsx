import { Button, Segmented, Select, TextArea, TextField } from '@octapass/ui';
import { useState } from 'react';
import { PasswordInput } from '../../components/PasswordInput';
import { t, type MessageKey } from '../../i18n';
import { downloadBlob } from '../../lib/download';
import { useConfirmIdentity } from '../../lib/identityGate';
import { bytesOf, Card, FileButton, KEY_TYPES, Output, readFile, SaveToVault, ToolError, useTool } from './shared';
import styles from './Tools.module.css';

type Kind = 'asymmetric' | 'jwt' | 'openpgp' | 'age';

const JWT_ALGORITHMS = ['ES256', 'ES384', 'EdDSA', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'HS256', 'HS384', 'HS512'];
/** The core's format names, and their message keys. */
const FORMATS: Record<string, string> = {
  'pkcs8-pem': 'pkcs8Pem',
  'pkcs8-der': 'pkcs8Der',
  'traditional-pem': 'traditionalPem',
  'openssh-private': 'opensshPrivate',
  jwk: 'jwk',
  'spki-pem': 'spkiPem',
  'spki-der': 'spkiDer',
  'pkcs1-public-pem': 'pkcs1PublicPem',
  'openssh-public': 'opensshPublic',
  'jwk-public': 'jwkPublic',
};

/** What a generator made, in the shape of a `key` item. */
interface Made {
  title: string;
  kind: Kind;
  algorithm: string;
  privateKey?: string;
  publicKey?: string;
  secret?: string;
  jwk?: string;
  jwks?: string;
  keyId?: string;
  fingerprint?: string;
  userId?: string;
}

function GenerateCard() {
  const { run, busy, error } = useTool();
  const [kind, setKind] = useState<Kind>('jwt');
  const [keyType, setKeyType] = useState('ed25519');
  const [algorithm, setAlgorithm] = useState('ES256');
  const [userId, setUserId] = useState('');
  const [made, setMade] = useState<Made>();

  async function generate() {
    setMade(undefined);
    if (kind === 'asymmetric') {
      const key = await run<{ privateKey: string; publicPem: string; fingerprints: { sshSha256: string } }>('key.generate', { type: keyType });
      if (key) setMade({ title: t('tools.keys.titleFor', { name: keyType }), kind, algorithm: keyType, privateKey: key.privateKey, publicKey: key.publicPem, fingerprint: key.fingerprints.sshSha256 });
    } else if (kind === 'jwt') {
      const key = await run<Omit<Made, 'title' | 'kind' | 'algorithm'>>('jwt.generateKey', { algorithm });
      if (key) setMade({ ...key, title: t('tools.keys.titleFor', { name: algorithm }), kind, algorithm });
    } else if (kind === 'age') {
      const key = await run<{ identity: string; recipient: string }>('key.age', {});
      if (key) setMade({ title: t('tools.keys.ageTitle'), kind, algorithm: 'X25519', privateKey: key.identity, publicKey: key.recipient });
    } else {
      const key = await run<{ privateKey: string; publicKey: string; fingerprint: string; keyId: string; userId: string; algorithm: string }>('key.gpg', { userId });
      if (key) setMade({ ...key, title: key.userId, kind });
    }
  }

  return (
    <Card title={t('tools.keys.generate')}>
      <div className={styles.row}>
        <Select
          label={t('tools.keys.kind')}
          value={kind}
          onChange={(e) => {
            setKind(e.target.value as Kind);
            setMade(undefined);
          }}
          options={(['jwt', 'asymmetric', 'openpgp', 'age'] as const).map((value) => ({ value, label: t(`tools.keys.kinds.${value}` as MessageKey) }))}
        />
        {kind === 'asymmetric' && <Select label={t('tools.keys.type')} value={keyType} onChange={(e) => setKeyType(e.target.value)} options={KEY_TYPES} />}
        {kind === 'jwt' && <Select label={t('tools.keys.algorithm')} value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} options={JWT_ALGORITHMS.map((value) => ({ value, label: value }))} />}
        {kind === 'openpgp' && <TextField label={t('tools.keys.userId')} placeholder="Ada Lovelace <ada@example.com>" value={userId} onChange={(e) => setUserId(e.target.value)} />}
      </div>
      <div className={styles.actions}>
        <Button icon="key" busy={busy} disabled={kind === 'openpgp' && !userId.trim()} onClick={() => void generate()}>
          {t('tools.keys.generateAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {made && (
        <>
          {made.keyId && <Output label={t('tools.keys.keyId')} value={made.keyId} />}
          {made.fingerprint && <Output label={t('tools.keys.fingerprint')} value={made.fingerprint} />}
          {made.publicKey && <Output label={t('tools.keys.publicKey')} value={made.publicKey} fileName="public-key.pem" />}
          {made.jwks && <Output label="JWKS" value={made.jwks} fileName="jwks.json" />}
          {made.privateKey && <Output label={t('tools.keys.privateKey')} value={made.privateKey} gated />}
          {made.secret && <Output label={t('tools.keys.secret')} value={made.secret} gated />}
          {made.jwk && <Output label="JWK" value={made.jwk} gated />}
          <SaveToVault
            key={made.keyId ?? made.publicKey}
            defaultTitle={made.title}
            makeDraft={(title) => run('item.key', { ...made, title })}
          />
        </>
      )}
    </Card>
  );
}

interface Converted {
  value: string;
  isPrivate: boolean;
  binary: boolean;
}

function ConvertCard() {
  const { run, busy, error } = useTool();
  const confirm = useConfirmIdentity();
  const [key, setKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [to, setTo] = useState('spki-pem');
  const [result, setResult] = useState<Converted>();
  const [fingerprints, setFingerprints] = useState<Record<string, string>>();

  async function convert() {
    setResult(await run<Converted>('key.convert', { key, passphrase: passphrase || undefined, to }));
    const inspected = await run<{ fingerprints: Record<string, string> }>('key.inspect', { key, passphrase: passphrase || undefined });
    setFingerprints(inspected?.fingerprints);
  }

  async function saveBinary() {
    if (!result) return;
    if (result.isPrivate && !(await confirm({ reason: t('identityGate.body') }))) return;
    downloadBlob(new Blob([bytesOf(result.value)], { type: 'application/octet-stream' }), 'key.der');
  }

  return (
    <Card title={t('tools.keys.convert')}>
      <TextArea label={t('tools.keys.input')} hint={t('tools.keys.inputHint')} mono dir="ltr" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} />
      <FileButton label={t('tools.keys.file')} onFile={(file) => void readFile(file).then(setKey)} />
      <div className={styles.row}>
        <PasswordInput label={t('tools.keys.passphrase')} autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
        <Select label={t('tools.keys.to')} value={to} onChange={(e) => setTo(e.target.value)} options={Object.entries(FORMATS).map(([value, key]) => ({ value, label: t(`tools.keys.formats.${key}` as MessageKey) }))} />
      </div>
      <div className={styles.actions}>
        <Button busy={busy} disabled={!key.trim()} onClick={() => void convert()}>
          {t('tools.keys.convertAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {result && (result.binary ? <Button variant="secondary" icon="download" onClick={() => void saveBinary()}>{t('tools.download')}</Button> : <Output label={t('tools.keys.result')} value={result.value} gated={result.isPrivate} />)}
      {fingerprints && (
        <>
          <Output label="SSH" value={fingerprints.sshSha256!} />
          <Output label="SPKI SHA-256" value={fingerprints.spkiSha256!} />
          <Output label={t('tools.keys.thumbprint')} value={fingerprints.jwkThumbprint!} />
        </>
      )}
    </Card>
  );
}

export function KeysPanel() {
  const [mode, setMode] = useState<'generate' | 'convert'>('generate');
  return (
    <div className={styles.panel}>
      <Segmented
        label={t('tools.panels.keys')}
        value={mode}
        onChange={setMode}
        block
        options={[
          { value: 'generate', label: t('tools.keys.generate') },
          { value: 'convert', label: t('tools.keys.convert') },
        ]}
      />
      {mode === 'generate' ? <GenerateCard /> : <ConvertCard />}
    </div>
  );
}
