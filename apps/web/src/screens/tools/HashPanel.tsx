import { Button, Segmented, TextArea, TextField } from '@octapass/ui';
import type { ToolHash } from '@octapass/vault-client';
import { useState } from 'react';
import { t } from '../../i18n';
import { Card, FileButton, Output, ToolError, toolError, useTool } from './shared';
import styles from './Tools.module.css';

type Mode = 'hash' | 'hmac';

/** Hashes of text or a file, HMAC, and comparing against a published checksum. */
export function HashPanel() {
  const { toolkit, run, busy, error, setError } = useTool();
  const [mode, setMode] = useState<Mode>('hash');
  const [text, setText] = useState('');
  const [key, setKey] = useState('');
  const [checksum, setChecksum] = useState('');
  const [hashes, setHashes] = useState<ToolHash[]>();
  const [comparison, setComparison] = useState<boolean>();

  function compare(found: ToolHash[]) {
    const wanted = checksum.trim().split(/\s+/)[0]?.toLowerCase();
    setComparison(wanted ? found.some((hash) => hash.hex === wanted || hash.base64.toLowerCase() === wanted) : undefined);
  }

  async function hashText() {
    if (mode === 'hmac') {
      const answer = await run<ToolHash>('hash.hmac', { algorithm: 'sha256', key: { value: key }, text });
      setHashes(answer ? [answer] : undefined);
      return;
    }
    const answer = await run<{ hashes: ToolHash[] }>('hash.digest', { text });
    setHashes(answer?.hashes);
    if (answer) compare(answer.hashes);
  }

  async function hashFile(file: File) {
    setError(undefined);
    try {
      const found = await toolkit.hashFile!(file, []);
      setHashes(found);
      compare(found);
    } catch (e) {
      setError(toolError(e));
    }
  }

  return (
    <Card>
      <Segmented
        label={t('tools.hash.mode')}
        value={mode}
        onChange={setMode}
        options={[
          { value: 'hash', label: t('tools.hash.hash') },
          { value: 'hmac', label: 'HMAC-SHA-256' },
        ]}
      />
      <TextArea label={t('tools.hash.input')} mono dir="ltr" value={text} onChange={(e) => setText(e.target.value)} />
      {mode === 'hmac' ? (
        <TextField label={t('tools.hash.key')} type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} />
      ) : (
        <TextField label={t('tools.hash.checksum')} hint={t('tools.hash.checksumHint')} dir="ltr" value={checksum} onChange={(e) => setChecksum(e.target.value)} />
      )}
      <div className={styles.actions}>
        <Button busy={busy} disabled={mode === 'hmac' && !key} onClick={() => void hashText()}>
          {t('tools.hash.run')}
        </Button>
        {toolkit.hashFile && mode === 'hash' && <FileButton label={t('tools.hash.file')} onFile={(file) => void hashFile(file)} />}
      </div>
      <ToolError message={error} />
      {comparison !== undefined && <p className={comparison ? styles.ok : styles.bad}>{t(comparison ? 'tools.hash.match' : 'tools.hash.mismatch')}</p>}
      {hashes?.map((hash) => (
        <div key={hash.algorithm}>
          <Output label={hash.algorithm} value={hash.hex} />
          {hash.legacy && <p className={styles.legacy}>{t('tools.hash.legacy')}</p>}
        </div>
      ))}
    </Card>
  );
}
