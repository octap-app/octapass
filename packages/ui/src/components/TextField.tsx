import { useId, type InputHTMLAttributes, type ReactNode, type Ref, type TextareaHTMLAttributes } from 'react';
import { Icon } from './Icon';
import styles from './TextField.module.css';

interface FieldChrome {
  label: ReactNode;
  /** Visually hide the label but keep it for screen readers. */
  hideLabel?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  /** Buttons shown inside the field, after the text (reveal, copy, generate). */
  actions?: ReactNode;
  mono?: boolean;
}

export type TextFieldProps = FieldChrome & Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> & { ref?: Ref<HTMLInputElement> };
export type TextAreaProps = FieldChrome & TextareaHTMLAttributes<HTMLTextAreaElement> & { ref?: Ref<HTMLTextAreaElement> };

// Addresses, numbers, codes and passwords read left to right in every language.
const LTR_TYPES = new Set(['email', 'url', 'password', 'tel', 'number']);
const LTR_MODES = new Set(['email', 'url', 'tel', 'numeric', 'decimal']);

function dataDirection({ type, inputMode, mono }: { type?: string | undefined; inputMode?: string | undefined; mono?: boolean | undefined }): 'ltr' | undefined {
  return mono || LTR_TYPES.has(type ?? '') || LTR_MODES.has(inputMode ?? '') ? 'ltr' : undefined;
}

function useFieldIds(id: string | undefined, hint: ReactNode, error: ReactNode) {
  const auto = useId();
  const fieldId = id ?? auto;
  return {
    fieldId,
    hintId: hint ? `${fieldId}-hint` : undefined,
    errorId: error ? `${fieldId}-error` : undefined,
  };
}

function Chrome({ label, hideLabel, hint, error, fieldId, hintId, errorId, children }: FieldChrome & ReturnType<typeof useFieldIds> & { children: ReactNode }) {
  return (
    <div className={styles.field}>
      <label htmlFor={fieldId} className={hideLabel ? 'visually-hidden' : styles.label}>
        {label}
      </label>
      {children}
      {error ? (
        <p id={errorId} className={styles.error}>
          <Icon name="alert" size={15} />
          {error}
        </p>
      ) : (
        hint && (
          <p id={hintId} className={styles.hint}>
            {hint}
          </p>
        )
      )}
    </div>
  );
}

export function TextField({ label, hideLabel, hint, error, actions, mono, id, className, ...input }: TextFieldProps) {
  const ids = useFieldIds(id, hint, error);
  return (
    <Chrome label={label} hideLabel={hideLabel} hint={hint} error={error} {...ids}>
      <div className={[styles.control, error && styles.invalid, className].filter(Boolean).join(' ')}>
        <input
          id={ids.fieldId}
          className={[styles.input, mono && 'mono'].filter(Boolean).join(' ')}
          aria-invalid={error ? true : undefined}
          aria-describedby={ids.errorId ?? ids.hintId}
          dir={dataDirection({ type: input.type, inputMode: input.inputMode, mono })}
          {...input}
        />
        {actions && <div className={styles.actions}>{actions}</div>}
      </div>
    </Chrome>
  );
}

export function TextArea({ label, hideLabel, hint, error, actions, mono, id, className, rows = 4, ...input }: TextAreaProps) {
  const ids = useFieldIds(id, hint, error);
  return (
    <Chrome label={label} hideLabel={hideLabel} hint={hint} error={error} {...ids}>
      <div className={[styles.control, styles.multiline, error && styles.invalid, className].filter(Boolean).join(' ')}>
        <textarea
          id={ids.fieldId}
          rows={rows}
          className={[styles.input, mono && 'mono'].filter(Boolean).join(' ')}
          aria-invalid={error ? true : undefined}
          aria-describedby={ids.errorId ?? ids.hintId}
          dir={dataDirection({ inputMode: input.inputMode, mono })}
          {...input}
        />
        {actions && <div className={styles.actions}>{actions}</div>}
      </div>
    </Chrome>
  );
}
