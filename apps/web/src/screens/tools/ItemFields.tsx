import { TextArea } from '@octapass/ui';
import type { CertificateDetails, Item, KeyItemDetails } from '@octapass/vault-client';
import { t } from '../../i18n';
import { CustomFieldsSection, Section, type SectionProps } from '../vault/EditorSections';
import { Field, FieldList, SecretField } from '../vault/Fields';

// Certificate and Key items in the vault. Private parts go through `SecretField`, which asks the
// user to confirm it's them before showing or copying (plan 16 §6).

export function CertificateFields({ item }: { item: Item; guard?: boolean }) {
  const details = item.details as CertificateDetails;
  return (
    <FieldList>
      <Field label={t('tools.certs.names')} value={details.sans?.join(', ')} ltr />
      <Field label={t('tools.certs.expires')} value={details.notAfter} copy={false} ltr />
      <Field label={t('tools.certs.key')} value={details.keyType} copy={false} ltr />
      <Field label={t('tools.certs.issuer')} value={details.issuer} ltr />
      <Field label="SHA-256" value={details.fingerprint} mono ltr />
      <Field label={t('tools.certs.certificate')} value={details.certificate} mono multiline ltr />
      <Field label={t('tools.certs.chain')} value={details.chain} mono multiline ltr />
      <SecretField label={t('tools.certs.privateKey')} value={details.privateKey} />
      <Field label={t('fields.notes')} value={details.notes} multiline />
    </FieldList>
  );
}

export function KeyFields({ item }: { item: Item; guard?: boolean }) {
  const details = item.details as KeyItemDetails;
  return (
    <FieldList>
      <Field label={t('tools.keys.algorithm')} value={details.algorithm} copy={false} ltr />
      <Field label={t('tools.keys.keyId')} value={details.keyId} mono ltr />
      <Field label={t('tools.keys.fingerprint')} value={details.fingerprint} mono ltr />
      <Field label={t('tools.keys.userId')} value={details.userId} ltr />
      <Field label={t('tools.keys.publicKey')} value={details.publicKey} mono multiline ltr />
      <Field label="JWKS" value={details.jwks} mono multiline ltr />
      <SecretField label={t('tools.keys.privateKey')} value={details.privateKey} />
      <SecretField label={t('tools.keys.secret')} value={details.secret} />
      <SecretField label="JWK" value={details.jwk} />
      <SecretField label={t('tools.keys.passphrase')} value={details.passphrase} />
      <Field label={t('fields.notes')} value={details.notes} multiline />
    </FieldList>
  );
}

/** The editor's part for these items: what was generated stays as it is. */
export function ToolItemSection({ draft, setDraft }: Omit<SectionProps, 'fieldError'>) {
  const details = draft.details as CertificateDetails | KeyItemDetails;
  const set = (patch: Partial<CertificateDetails>) => setDraft((d) => ({ ...d, details: { ...d.details, ...patch } }));
  return (
    <>
      <CustomFieldsSection fields={details.customFields} onChange={(customFields) => set({ customFields })} />
      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>
    </>
  );
}
