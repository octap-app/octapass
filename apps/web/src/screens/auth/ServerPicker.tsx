import { Segmented, TextField } from '@octapass/ui';
import { DEFAULT_SERVER_URL } from '../../app/service';
import { t } from '../../i18n';
import styles from './ServerPicker.module.css';

export interface ServerChoice {
  kind: 'hosted' | 'self';
  url: string;
}

export const HOSTED: ServerChoice = { kind: 'hosted', url: DEFAULT_SERVER_URL };

export function serverUrlOf(choice: ServerChoice): string {
  return choice.kind === 'hosted' ? DEFAULT_SERVER_URL : choice.url.trim();
}

/** Octa Pass is the default; self-hosters type their server's HTTPS address (plan 05). */
export function ServerPicker({ value, onChange, error }: { value: ServerChoice; onChange: (value: ServerChoice) => void; error?: string }) {
  return (
    <fieldset className={styles.picker}>
      <legend className="visually-hidden">{t('server.legend')}</legend>
      <Segmented
        block
        label={t('server.legend')}
        value={value.kind}
        onChange={(kind) => onChange({ kind, url: kind === 'self' ? (value.kind === 'self' ? value.url : 'https://') : DEFAULT_SERVER_URL })}
        options={[
          { value: 'hosted', label: t('server.hosted') },
          { value: 'self', label: t('server.selfHosted') },
        ]}
      />
      {value.kind === 'self' && (
        <TextField
          label={t('server.urlLabel')}
          type="url"
          inputMode="url"
          autoComplete="url"
          spellCheck={false}
          placeholder="https://vault.example.com"
          value={value.url}
          onChange={(e) => onChange({ kind: 'self', url: e.target.value })}
          hint={t('server.urlHint')}
          error={error}
        />
      )}
    </fieldset>
  );
}
