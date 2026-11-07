import { Button, Select, TextField } from '@octapass/ui';
import { useState } from 'react';
import { t, type MessageKey } from '../../i18n';
import { Card, Output, SaveToVault, ToolError, useTool } from './shared';
import styles from './Tools.module.css';

const SHAPES = ['base62', 'hex', 'base64url', 'nanoid', 'uuid4', 'uuid7', 'ulid'] as const;
type Shape = (typeof SHAPES)[number];

/** Random tokens, API keys and identifiers. `save`: offer saving as an API credential. */
export function RandomPanel({ save = true }: { save?: boolean }) {
  const { run, busy, error } = useTool();
  const [shape, setShape] = useState<Shape>('base62');
  const [prefix, setPrefix] = useState('');
  const [length, setLength] = useState('');
  const [token, setToken] = useState<{ value: string; entropyBits: number }>();

  async function make() {
    const parsed = Number.parseInt(length, 10);
    setToken(await run('random.token', { shape, prefix: prefix || undefined, length: Number.isNaN(parsed) ? undefined : parsed }));
  }

  const sized = shape === 'base62' || shape === 'hex' || shape === 'base64url' || shape === 'nanoid';
  return (
    <Card>
      <div className={styles.row}>
        <Select label={t('tools.random.shape')} value={shape} onChange={(e) => setShape(e.target.value as Shape)} options={SHAPES.map((value) => ({ value, label: t(`tools.random.shapes.${value}` as MessageKey) }))} />
        {sized && <TextField label={t('tools.random.length')} inputMode="numeric" value={length} onChange={(e) => setLength(e.target.value)} />}
        <TextField label={t('tools.random.prefix')} dir="ltr" placeholder="sk_live_" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
      </div>
      <div className={styles.actions}>
        <Button icon="refresh" busy={busy} onClick={() => void make()}>
          {t('tools.random.make')}
        </Button>
      </div>
      <ToolError message={error} />
      {token && (
        <>
          <Output label={t('tools.random.result')} value={token.value} />
          <p className={token.entropyBits < 128 ? styles.bad : styles.note}>{t('tools.random.bits', { bits: Math.round(token.entropyBits) })}</p>
          {save && (
            <SaveToVault
              key={token.value}
              defaultTitle={t('tools.random.defaultTitle')}
              makeDraft={async (title) => ({
                overview: { schemaVersion: 1, type: 'apiCredential' as never, title },
                details: { schemaVersion: 1, key: token.value } as never,
              })}
            />
          )}
        </>
      )}
    </Card>
  );
}
