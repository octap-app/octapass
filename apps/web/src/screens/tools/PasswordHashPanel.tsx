import { Button, Select, TextField } from '@octapass/ui';
import { useState } from 'react';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { Card, Output, ToolError, useTool } from './shared';
import styles from './Tools.module.css';

const SCHEMES = [
  { value: 'argon2id', label: 'Argon2id' },
  { value: 'bcrypt', label: 'bcrypt' },
  { value: 'scrypt', label: 'scrypt' },
  { value: 'pbkdf2', label: 'PBKDF2' },
];

/** Hashes for your own apps, and checking a password against one. Hashes aren't saved by default. */
export function PasswordHashPanel() {
  const { run, busy, error } = useTool();
  const [scheme, setScheme] = useState('argon2id');
  const [password, setPassword] = useState('');
  const [hash, setHash] = useState('');
  const [made, setMade] = useState<string>();
  const [matches, setMatches] = useState<boolean>();

  async function make() {
    setMatches(undefined);
    const answer = await run<{ hash: string }>('password.hash', { scheme, password });
    setMade(answer?.hash);
    if (answer) setHash(answer.hash);
  }

  async function verify() {
    const answer = await run<{ matches: boolean }>('password.verify', { password, hash });
    setMatches(answer?.matches);
  }

  return (
    <Card>
      <Select label={t('tools.passwordHash.scheme')} value={scheme} onChange={(e) => setScheme(e.target.value)} options={SCHEMES} />
      <PasswordInput label={t('tools.passwordHash.password')} autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} />
      <div className={styles.actions}>
        <Button busy={busy} disabled={!password} onClick={() => void make()}>
          {t('tools.passwordHash.make')}
        </Button>
      </div>
      {made && <Output label={t('tools.passwordHash.hash')} value={made} />}
      <TextField label={t('tools.passwordHash.existing')} mono dir="ltr" value={hash} onChange={(e) => setHash(e.target.value)} />
      <div className={styles.actions}>
        <Button variant="secondary" busy={busy} disabled={!password || !hash} onClick={() => void verify()}>
          {t('tools.passwordHash.verify')}
        </Button>
      </div>
      <ToolError message={error} />
      {matches !== undefined && <p className={matches ? styles.ok : styles.bad}>{t(matches ? 'tools.passwordHash.match' : 'tools.passwordHash.noMatch')}</p>}
    </Card>
  );
}
