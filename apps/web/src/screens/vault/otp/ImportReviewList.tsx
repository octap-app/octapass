import { Button, Icon } from '@octapass/ui';
import type { CodeLink, ImportReview, ItemSummary } from '@octapass/vault-client';
import { useState } from 'react';
import { t } from '../../../i18n';
import { LoginPicker } from './LoginPicker';
import { codeLabel } from './useQrScan';
import styles from './otp.module.css';

/** Where each code goes: a login's id, or `undefined` for a login of its own. */
export type CodeChoices = Record<number, string | undefined>;

/** The import's own matches, to start the review from. */
export function initialChoices(review: ImportReview): CodeChoices {
  return Object.fromEntries(review.codes.map((code) => [code.index, code.loginId]));
}

/** Every code with the user's choice, for `finishImport`. */
export function codeLinks(choices: CodeChoices): CodeLink[] {
  return Object.entries(choices).map(([code, loginId]) => ({ code: Number(code), ...(loginId ? { loginId } : {}) }));
}

export interface ImportReviewListProps {
  review: ImportReview;
  logins: ItemSummary[];
  choices: CodeChoices;
  onChange: (choices: CodeChoices) => void;
}

/**
 * One row per imported one-time code: the login it joins, or "separate item", with a searchable
 * picker to change it. A login takes one code.
 */
export function ImportReviewList({ review, logins, choices, onChange }: ImportReviewListProps) {
  const [open, setOpen] = useState<number>();
  return (
    <ul className={styles.review} aria-label={t('otp.reviewTitle')}>
      {review.codes.map((code) => {
        const loginId = choices[code.index];
        const login = logins.find((l) => l.id === loginId);
        const taken = new Set(Object.entries(choices).flatMap(([index, id]) => (Number(index) !== code.index && id ? [id] : [])));
        const expanded = open === code.index;
        return (
          <li key={code.index} className={styles.reviewRow}>
            <div className={styles.reviewHead}>
              <Icon name="clock" size={18} />
              <span className={styles.optionText}>
                <strong>
                  <bdi>{codeLabel(code)}</bdi>
                </strong>
                <small>
                  {login ? (
                    <>
                      <Icon name="link" size={13} /> {t('otp.goesTo', { title: login.title })}
                    </>
                  ) : (
                    t('otp.separate')
                  )}
                </small>
              </span>
              <Button variant="ghost" size="sm" aria-expanded={expanded} onClick={() => setOpen(expanded ? undefined : code.index)}>
                {expanded ? t('common.done') : t('otp.change')}
              </Button>
            </div>
            {expanded && (
              <LoginPicker
                logins={logins}
                value={loginId}
                taken={taken}
                label={t('otp.pickerLabel', { title: codeLabel(code) })}
                onChange={(next) => onChange({ ...choices, [code.index]: next })}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}
