import { StrengthMeter } from '@octapass/ui';
import type { StrengthEstimate } from '@octapass/vault-client';
import { t, type MessageKey } from '../i18n';

export function strengthLabel(score: StrengthEstimate['score']): string {
  return t(`strength.score.${score}` as MessageKey);
}

/** The meter plus one specific tip from the estimator, translated. */
export function StrengthHint({ estimate, empty }: { estimate: StrengthEstimate; empty?: boolean }) {
  const hint = estimate.feedback ? t(`strength.feedback.${estimate.feedback}` as MessageKey) : estimate.score >= 4 ? t('strength.great') : undefined;
  return <StrengthMeter score={estimate.score} empty={empty} label={empty ? t('strength.empty') : strengthLabel(estimate.score)} hint={empty ? undefined : hint} />;
}
