import { IconButton, TextField, type TextFieldProps } from '@octapass/ui';
import { useState, type ReactNode } from 'react';
import { t } from '../i18n';

export type PasswordInputProps = Omit<TextFieldProps, 'type' | 'actions'> & { extraActions?: ReactNode };

/** A password field with a reveal toggle. Revealed text switches to Monaspace so 0/O and l/1 differ. */
export function PasswordInput({ extraActions, mono, ...props }: PasswordInputProps) {
  const [revealed, setRevealed] = useState(false);
  return (
    <TextField
      {...props}
      type={revealed ? 'text' : 'password'}
      mono={mono ?? revealed}
      dir="ltr"
      spellCheck={false}
      autoCapitalize="off"
      autoCorrect="off"
      actions={
        <>
          {extraActions}
          <IconButton
            size="sm"
            icon={revealed ? 'eyeOff' : 'eye'}
            label={revealed ? t('common.hide') : t('common.reveal')}
            aria-pressed={revealed}
            onClick={() => setRevealed((r) => !r)}
          />
        </>
      }
    />
  );
}
