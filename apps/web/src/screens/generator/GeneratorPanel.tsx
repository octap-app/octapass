import { Button, IconButton, Segmented, Slider, Switch } from '@octapass/ui';
import { DEFAULT_PASSPHRASE_OPTIONS, DEFAULT_PASSWORD_OPTIONS, generatorEntropyBits, type GeneratorOptions } from '@octapass/vault-client';
import { useCallback, useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { strengthLabel } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import styles from './GeneratorPanel.module.css';

type PasswordOptions = Extract<GeneratorOptions, { kind: 'password' }>;
type PassphraseOptions = Extract<GeneratorOptions, { kind: 'passphrase' }>;

interface Stored {
  kind: GeneratorOptions['kind'];
  password: PasswordOptions;
  passphrase: PassphraseOptions;
}

const STORAGE_KEY = 'octapass:generator';

// Only the options are remembered, never a generated value.
function loadOptions(): Stored {
  const defaults: Stored = { kind: 'password', password: DEFAULT_PASSWORD_OPTIONS, passphrase: DEFAULT_PASSPHRASE_OPTIONS };
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Partial<Stored>;
    return { kind: stored.kind ?? defaults.kind, password: { ...defaults.password, ...stored.password }, passphrase: { ...defaults.passphrase, ...stored.passphrase } };
  } catch {
    return defaults;
  }
}

const SEPARATORS = ['-', ' ', '.', '_', ','] as const;

/** Colours digits and symbols differently so a generated password is easier to read out or type. */
function Highlighted({ value }: { value: string }) {
  return (
    <>
      {Array.from(value).map((char, i) => (
        <span key={i} className={/\d/.test(char) ? styles.digit : /[^\p{L}\d\s]/u.test(char) ? styles.symbol : undefined}>
          {char}
        </span>
      ))}
    </>
  );
}

/** `site`: the website the password is for, so a suggestion follows that site's known password rules. */
export function GeneratorPanel({ onUse, useLabel, site }: { onUse?: (value: string) => void; useLabel?: string; site?: string }) {
  const service = useService();
  const copy = useCopy();
  const [stored, setStored] = useState(loadOptions);
  const options: GeneratorOptions = stored.kind === 'password' ? stored.password : stored.passphrase;
  const generate = useCallback(() => service.generatePassword(options), [service, options]);
  const [value, setValue] = useState(generate);
  // The rules live in the core, which answers a moment later: the plain password holds the place.
  const regenerate = useCallback(() => {
    setValue(generate());
    if (site && options.kind === 'password') service.generatePasswordForSite?.(site, options).then(setValue, () => undefined);
  }, [service, generate, site, options]);

  useEffect(() => {
    regenerate();
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    } catch {
      // Storage can be unavailable; the options still work for this visit.
    }
  }, [stored, regenerate]);

  const estimate = service.estimateStrength(value);
  const bits = Math.round(generatorEntropyBits(options));
  const setPassword = (patch: Partial<PasswordOptions>) => setStored((s) => ({ ...s, password: { ...s.password, ...patch } }));
  const setPassphrase = (patch: Partial<PassphraseOptions>) => setStored((s) => ({ ...s, passphrase: { ...s.passphrase, ...patch } }));

  return (
    <div className={styles.panel}>
      <div className={styles.output}>
        <p className={`mono ${styles.value}`} aria-live="polite" aria-label={t('generator.generated')}>
          <Highlighted value={value} />
        </p>
        <div className={styles.outputFoot}>
          <span className={styles.meta} data-score={estimate.score}>
            <span className={styles.dot} />
            {strengthLabel(estimate.score)} · {t('generator.bits', { bits })}
          </span>
          <span className={styles.outputActions}>
            <IconButton icon="refresh" label={t('generator.regenerate')} onClick={regenerate} />
            <IconButton icon="copy" label={t('copy.action', { what: t('fields.password') })} onClick={() => void copy(value, t('fields.password'))} />
          </span>
        </div>
      </div>

      <Segmented
        block
        label={t('generator.kind')}
        value={stored.kind}
        onChange={(kind) => setStored((s) => ({ ...s, kind }))}
        options={[
          { value: 'password', label: t('generator.password') },
          { value: 'passphrase', label: t('generator.passphrase') },
        ]}
      />

      {options.kind === 'password' ? (
        <div className={styles.options}>
          <Slider label={t('generator.length')} min={8} max={64} value={options.length} onChange={(length) => setPassword({ length })} valueText={t('generator.lengthValue', { count: options.length })} />
          <Switch label={t('generator.uppercase')} checked={options.uppercase} onChange={(uppercase) => setPassword({ uppercase })} />
          <Switch label={t('generator.lowercase')} checked={options.lowercase} onChange={(lowercase) => setPassword({ lowercase })} />
          <Switch label={t('generator.digits')} checked={options.digits} onChange={(digits) => setPassword({ digits })} />
          <Switch label={t('generator.symbols')} checked={options.symbols} onChange={(symbols) => setPassword({ symbols })} />
          <Switch label={t('generator.avoidAmbiguous')} description={t('generator.avoidAmbiguousHint')} checked={options.avoidAmbiguous} onChange={(avoidAmbiguous) => setPassword({ avoidAmbiguous })} />
        </div>
      ) : (
        <div className={styles.options}>
          <Slider label={t('generator.words')} min={3} max={10} value={options.words} onChange={(words) => setPassphrase({ words })} valueText={t('generator.wordsValue', { count: options.words })} />
          <div className={styles.separator}>
            <span aria-hidden="true">{t('generator.separator')}</span>
            <Segmented
              label={t('generator.separator')}
              value={options.separator}
              onChange={(separator) => setPassphrase({ separator })}
              options={SEPARATORS.map((s) => ({ value: s, label: s === ' ' ? t('generator.space') : <span className="mono">{s}</span> }))}
            />
          </div>
          <Switch label={t('generator.capitalize')} checked={options.capitalize} onChange={(capitalize) => setPassphrase({ capitalize })} />
          <Switch label={t('generator.includeNumber')} checked={options.includeNumber} onChange={(includeNumber) => setPassphrase({ includeNumber })} />
        </div>
      )}

      {onUse && (
        <Button size="lg" block icon="check" onClick={() => onUse(value)}>
          {useLabel ?? t('generator.use')}
        </Button>
      )}
    </div>
  );
}
