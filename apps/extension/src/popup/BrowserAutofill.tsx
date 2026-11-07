import { Button, Switch } from '@octapass/ui';
import { Alert } from '@octapass/web/src/components/Alert';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import webStyles from '@octapass/web/src/screens/settings/SettingsPage.module.css';
import { useCallback, useEffect, useState } from 'react';
import { tx } from '../i18n';
import {
  apply,
  BROWSER_FEATURES,
  browserName,
  chromeApis,
  loadChoice,
  readStates,
  requestPermission,
  restore,
  saveChoice,
  supportedFeatures,
  type BrowserApis,
  type BrowserAutofillChoice,
  type BrowserFeature,
  type FeatureState,
} from './browserSettings';
import styles from './BrowserAutofill.module.css';

/** The user's choice and what the browser says, kept together; `turnOn` must run inside a click. */
function useBrowserAutofill(apis: BrowserApis) {
  const [choice, setChoice] = useState<BrowserAutofillChoice>();
  const [states, setStates] = useState<Record<BrowserFeature, FeatureState>>();
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    void loadChoice().then(setChoice);
    void readStates(apis).then(setStates);
  }, [apis]);

  const update = useCallback(
    async (next: BrowserAutofillChoice, permission?: Promise<boolean>) => {
      setChoice(next);
      setDenied(false);
      if (next.on) {
        if (permission && !(await permission)) {
          setDenied(true);
          next = { ...next, on: false };
          setChoice(next);
        } else {
          setStates(await apply(apis, next.features));
        }
      } else {
        await restore(apis);
        setStates(await readStates(apis));
      }
      await saveChoice(next);
    },
    [apis],
  );

  /** Turning on asks for the permission first thing, while the click still counts as a gesture. */
  const turnOn = (base: BrowserAutofillChoice) => {
    const permission = requestPermission(apis);
    return update({ ...base, on: true, offered: true, features: base.features.length ? base.features : BROWSER_FEATURES }, permission);
  };

  return { choice, states, denied, update, turnOn };
}

const FEATURE_LABEL: Record<BrowserFeature, () => string> = {
  passwords: () => tx('browser.passwords'),
  addresses: () => tx('browser.addresses'),
  cards: () => tx('browser.cards'),
};

function heldBy(state: FeatureState | undefined, browser: string): string | undefined {
  if (state === 'otherExtension') return tx('browser.otherExtension', { browser });
  if (state === 'policy') return tx('browser.policy', { browser });
  return undefined;
}

/** Settings: Octa Pass instead of the browser's own password manager, per feature. */
export function BrowserAutofillSection({ apis = chromeApis() }: { apis?: BrowserApis }) {
  const [stableApis] = useState(apis);
  const { choice, states, denied, update, turnOn } = useBrowserAutofill(stableApis);
  const browser = browserName();
  const supported = supportedFeatures(stableApis);

  if (supported.length === 0) {
    return (
      <Section id="browser" title={tx('browser.title')}>
        <Row label={tx('browser.useOctaPass', { browser })} description={tx('browser.safari')} />
      </Section>
    );
  }
  if (!choice) return null;
  const toggle = (feature: BrowserFeature, on: boolean) => {
    const features = on ? [...new Set([...choice.features, feature])] : choice.features.filter((f) => f !== feature);
    void update({ ...choice, features });
  };

  return (
    <Section id="browser" title={tx('browser.title')}>
      <div className={webStyles.row}>
        <Switch
          label={tx('browser.useOctaPass', { browser })}
          description={tx('browser.useOctaPassHelp', { browser })}
          checked={choice.on}
          onChange={(on) => void (on ? turnOn(choice) : update({ ...choice, on: false, offered: true }))}
        />
      </div>
      {denied && (
        <div className={webStyles.row}>
          <Alert tone="warn">{tx('browser.denied', { browser })}</Alert>
        </div>
      )}
      {choice.on &&
        supported.map((feature) => (
          <div key={feature} className={webStyles.row}>
            <Switch
              label={FEATURE_LABEL[feature]()}
              description={heldBy(states?.[feature], browser)}
              checked={choice.features.includes(feature)}
              disabled={states?.[feature] === 'otherExtension' || states?.[feature] === 'policy'}
              onChange={(on) => toggle(feature, on)}
            />
          </div>
        ))}
      {choice.on && !supported.includes('addresses') && <Row label={tx('browser.firefoxForms')} />}
    </Section>
  );
}

/** Shown once after unlocking until answered: the same switch as in the settings, as a question. */
export function BrowserAutofillOffer({ apis = chromeApis() }: { apis?: BrowserApis }) {
  const [stableApis] = useState(apis);
  const { choice, update, turnOn } = useBrowserAutofill(stableApis);
  if (!choice || choice.offered || choice.on || supportedFeatures(stableApis).length === 0) return null;
  const browser = browserName();
  return (
    <div className={styles.banner}>
      <Alert
        tone="info"
        action={
          <span className={styles.actions}>
            <Button variant="secondary" size="sm" onClick={() => void update({ ...choice, offered: true })}>
              {tx('browser.notNow')}
            </Button>
            <Button size="sm" onClick={() => void turnOn(choice)}>
              {tx('browser.turnOn')}
            </Button>
          </span>
        }
      >
        <strong>{tx('browser.offerTitle', { browser })}</strong> {tx('browser.offerBody')}
      </Alert>
    </div>
  );
}
