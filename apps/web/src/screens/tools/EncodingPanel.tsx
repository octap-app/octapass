import { Button, Select, TextArea } from '@octapass/ui';
import { useState } from 'react';
import { t } from '../../i18n';
import { Card, Output, ToolError, useTool } from './shared';
import styles from './Tools.module.css';

const FORMATS = ['base64', 'base64url', 'base32', 'hex', 'url', 'html', 'unicode'];

interface Candidate {
  format: string;
  confidence: number;
  text?: string;
  hex?: string;
}

/** Encode, decode, and a guess at what pasted text is. */
export function EncodingPanel() {
  const { run, busy, error } = useTool();
  const [format, setFormat] = useState('base64');
  const [text, setText] = useState('');
  const [result, setResult] = useState<string>();
  const [candidates, setCandidates] = useState<Candidate[]>();

  async function encode() {
    setCandidates(undefined);
    const answer = await run<{ value: string }>('encoding.encode', { format, text });
    setResult(answer?.value);
  }

  async function decode() {
    setCandidates(undefined);
    const answer = await run<{ text?: string; hex: string }>('encoding.decode', { format, value: text });
    setResult(answer ? (answer.text ?? answer.hex) : undefined);
  }

  async function detect() {
    setResult(undefined);
    const answer = await run<{ candidates: Candidate[] }>('encoding.detect', { value: text });
    setCandidates(answer?.candidates);
  }

  return (
    <Card>
      <Select label={t('tools.encoding.format')} value={format} onChange={(e) => setFormat(e.target.value)} options={FORMATS.map((value) => ({ value, label: value }))} />
      <TextArea label={t('tools.encoding.input')} mono dir="ltr" value={text} onChange={(e) => setText(e.target.value)} />
      <div className={styles.actions}>
        <Button busy={busy} disabled={!text} onClick={() => void encode()}>
          {t('tools.encoding.encode')}
        </Button>
        <Button variant="secondary" disabled={!text} onClick={() => void decode()}>
          {t('tools.encoding.decode')}
        </Button>
        <Button variant="ghost" disabled={!text} onClick={() => void detect()}>
          {t('tools.encoding.detect')}
        </Button>
      </div>
      <ToolError message={error} />
      {result !== undefined && <Output label={t('tools.encoding.result')} value={result} />}
      {candidates && (
        <ul className={styles.list}>
          {candidates.length === 0 && <li>{t('tools.encoding.none')}</li>}
          {candidates.map((candidate) => (
            <li key={candidate.format}>
              <strong>{candidate.format}</strong> <span className={styles.note}>{t('tools.encoding.confidence', { percent: candidate.confidence })}</span>
              {(candidate.text ?? candidate.hex) && <Output label={candidate.format} value={(candidate.text ?? candidate.hex)!} />}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
