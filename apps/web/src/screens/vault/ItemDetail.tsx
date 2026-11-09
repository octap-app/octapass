import { Button, Dialog, EmptyState, Icon, IconButton, Spinner, useToast } from '@octapass/ui';
import {
  DEFAULT_URL_MATCH_MODE,
  hostnameOf,
  isVaultError,
  itemDates,
  type CardDetails,
  type CustomDetails,
  type CustomTemplateDetails,
  type DocumentDetails,
  type HealthEntry,
  type IdentityDetails,
  type Item,
  type LoginDetails,
  type RecoverySource,
  type SecureNoteDetails,
  type Vault,
  uniqueWebsites,
} from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { Menu, type MenuItem } from '../../components/Menu';
import { formatDate, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealthReport } from '../../lib/health';
import { providerName } from '../../lib/maskedEmail';
import { ItemAvatar } from '../../lib/siteIcons';
import { ItemUseProvider, useRecordItemUse } from '../../lib/usage';
import { useVaults } from '../../lib/useItems';
import { useSharing } from '../../lib/useSharing';
import { ChangePasswordDialog } from '../health/ChangePasswordDialog';
import { Row as HealthRow } from '../health/HealthRow';
import healthStyles from '../health/HealthPage.module.css';
import { MoveCopyDialog } from '../sharing/MoveCopyDialog';
import { ShareLinkDialog } from '../sharing/ShareLinkDialog';
import { EnvironmentFields } from './Environment';
import { Field, FieldList, SecretField, TotpField } from './Fields';
import { ItemFiles, useAttachments } from './Files';
import { ItemHistory } from './ItemHistory';
import { ItemPlaces, PlaceSuggestion } from './Nearby';
import { AddCodeDialog } from './otp/AddCodeDialog';
import { LinkToLoginDialog } from './otp/LinkToLoginDialog';
import { isCodeOnly } from './otp/useQrScan';
import { SshKeyFields } from './SshKeys';
import { CertificateFields, KeyFields } from '../tools/ItemFields';
import { CustomFields, TableFields, TemplateFields } from './TypedItems';
import { WifiFields } from './Wifi';
import styles from './ItemDetail.module.css';

const TRASH_DAYS = 30;

/** Loads one item and keeps it fresh when the vault changes (edits, restores, other tabs). */
export function useItem(id: string | undefined): { item: Item | undefined; error: unknown } {
  const service = useService();
  const [state, setState] = useState<{ item: Item | undefined; error: unknown; id?: string }>({ item: undefined, error: undefined });

  useEffect(() => {
    if (!id) return;
    let live = true;
    const load = () =>
      service.getItem(id).then(
        (item) => live && setState({ item, error: undefined, id }),
        (error: unknown) => live && setState({ item: undefined, error, id }),
      );
    void load();
    const unsubscribe = service.onItemsChange(() => void load());
    return () => {
      live = false;
      unsubscribe();
    };
  }, [service, id]);

  return state.id === id ? state : { item: undefined, error: undefined };
}

export function formatCardNumber(number: string): string {
  return number.replace(/\s/g, '').replace(/(.{4})(?=.)/g, '$1 ');
}

export function ItemDetail() {
  const { itemId, scope = 'all' } = useParams();
  const { item, error } = useItem(itemId);
  const vaults = useVaults();
  const service = useService();
  const toast = useToast();
  const navigate = useNavigate();
  const sharing = useSharing();
  const attachments = useAttachments();
  const [busy, setBusy] = useState(false);
  const [sharingLink, setSharingLink] = useState(false);
  const [moveCopy, setMoveCopy] = useState<'move' | 'copy'>();
  const [codeDialog, setCodeDialog] = useState<'add' | 'link'>();
  // Set by the editor right after it saves a new item: Nearby may offer it a place.
  const created = (useLocation().state as { created?: string } | null)?.created;
  const listPath = `/items/${scope}`;

  if (error) {
    return (
      <EmptyState
        icon="alert"
        title={isVaultError(error, 'notFound') ? t('detail.notFound') : t('detail.loadFailed')}
        action={<Button variant="secondary" onClick={() => navigate(listPath)}>{t('detail.backToList')}</Button>}
      >
        {isVaultError(error, 'notFound') ? t('detail.notFoundBody') : errorMessage(error)}
      </EmptyState>
    );
  }
  if (!item) {
    return (
      <div className={styles.loading} aria-busy="true" aria-label={t('common.loading')}>
        <Spinner size={24} />
      </div>
    );
  }

  const vault = vaults?.find((v) => v.id === item.vaultId);
  const readOnly = vault?.role === 'read';
  const trashed = Boolean(item.deletedAt);
  const host = item.overview.urls?.[0] ? hostnameOf(item.overview.urls[0]) : undefined;

  async function run(action: () => Promise<unknown>, message: string, after?: () => void) {
    setBusy(true);
    try {
      await action();
      toast({ message, tone: 'success' });
      after?.();
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  const toggleFavorite = () =>
    run(
      () => service.saveItem({ ...item, overview: { ...item.overview, favorite: !item.overview.favorite } }),
      item.overview.favorite ? t('detail.unfavorited') : t('detail.favorited'),
    );
  const togglePinned = () =>
    run(
      () => service.saveItem({ ...item, overview: { ...item.overview, pinned: !item.overview.pinned } }),
      item.overview.pinned ? t('detail.unpinned') : t('detail.pinned'),
    );
  const moveToTrash = () => run(() => service.deleteItem(item.id), t('detail.trashed', { title: item.overview.title }), () => navigate(listPath));
  const restore = () => run(() => service.restoreItem(item.id), t('detail.restored', { title: item.overview.title }), () => navigate(`/items/all/${item.id}`));
  // A document's file is the point of it, so it comes first; other items list files after their fields.
  const isDocument = item.overview.type === 'document';
  const editable = !trashed && !readOnly && !vault?.untrusted;
  const isLogin = item.overview.type === 'login' || item.overview.type === 'password';
  // A one-time code without opening the editor: add one to a login, or move a code that came in on
  // an item of its own (an authenticator import, a scan) into the login it belongs to.
  const canAddCode = editable && isLogin && !(item.details as LoginDetails).totp;
  const canLinkCode = editable && isCodeOnly(item);
  const codeActions = (canAddCode || canLinkCode) && (
    <div className={styles.codeActions}>
      {canAddCode && (
        <Button variant="secondary" size="sm" icon="plus" onClick={() => setCodeDialog('add')}>
          {t('otp.addCode')}
        </Button>
      )}
      {canLinkCode && (
        <Button variant="secondary" size="sm" icon="link" onClick={() => setCodeDialog('link')}>
          {t('otp.linkAction')}
        </Button>
      )}
    </div>
  );
  const files = attachments && <ItemFiles item={item} attachments={attachments} editable={!trashed && !readOnly && !vault?.untrusted} />;
  const otherVaults = (vaults ?? []).some((v) => v.id !== item.vaultId && v.role !== 'read' && !v.untrusted);
  const moreItems: MenuItem[] = sharing && !trashed
    ? [
        { key: 'share', label: t('shareLink.action'), icon: 'link', onSelect: () => setSharingLink(true) },
        ...(otherVaults && !readOnly ? [{ key: 'move', label: t('moveCopy.move'), icon: 'move' as const, onSelect: () => setMoveCopy('move') }] : []),
        ...(otherVaults ? [{ key: 'copy', label: t('moveCopy.copy'), icon: 'copy' as const, onSelect: () => setMoveCopy('copy') }] : []),
      ]
    : [];

  return (
    <ItemUseProvider itemId={item.id}>
      <article className={styles.detail} aria-labelledby="item-title">
        <div className={styles.toolbar}>
          <Link to={listPath} className={styles.back}>
            <Icon name="chevronLeft" size={20} />
            {t('detail.back')}
          </Link>
          <div className={styles.tools}>
            {!trashed && !readOnly && (
              <>
                <IconButton
                  icon="star"
                  label={item.overview.favorite ? t('detail.removeFavorite') : t('detail.addFavorite')}
                  aria-pressed={Boolean(item.overview.favorite)}
                  className={item.overview.favorite ? styles.starOn : undefined}
                  disabled={busy}
                  onClick={toggleFavorite}
                />
                <IconButton
                  icon="pin"
                  label={item.overview.pinned ? t('detail.unpin') : t('detail.pin')}
                  aria-pressed={Boolean(item.overview.pinned)}
                  className={item.overview.pinned ? styles.pinOn : undefined}
                  disabled={busy}
                  onClick={togglePinned}
                />
                <IconButton icon="trash" label={t('detail.moveToTrash')} tone="danger" disabled={busy} onClick={moveToTrash} />
                <Button variant="secondary" size="sm" icon="edit" onClick={() => navigate(`${listPath}/${item.id}/edit`)}>
                  {t('common.edit')}
                </Button>
              </>
            )}
            {moreItems.length > 0 && <Menu label={t('detail.more')} items={moreItems} trigger={(props) => <IconButton icon="more" label={t('detail.more')} {...props} />} />}
            {trashed && (
              <Button size="sm" icon="restore" busy={busy} onClick={restore}>
                {t('trash.restore')}
              </Button>
            )}
          </div>
        </div>

        <div className={styles.content}>
          {trashed && (
            <Alert tone="warn">
              {t('trash.itemNotice', { count: Math.max(0, Math.ceil(TRASH_DAYS - (Date.now() - Date.parse(item.deletedAt!)) / 86_400_000)) })}
            </Alert>
          )}
          {readOnly && <Alert tone="info">{t('detail.readOnly', { vault: vault?.name ?? '' })}</Alert>}
          {editable && <PlaceSuggestion item={item} fresh={created === item.id} />}

          <header className={styles.head}>
            <ItemAvatar name={item.overview.title} urls={item.overview.urls} size="xl" />
            <div className={styles.headText}>
              <h1 id="item-title" className={styles.title}>
                <bdi>{item.overview.title || t('detail.untitled')}</bdi>
              </h1>
              <p className={styles.sub}>{host ? <bdi dir="ltr">{host}</bdi> : t(`types.${item.overview.type}` as MessageKey)}</p>
            </div>
            <span className={styles.sealed}>
              <Icon name="lock" size={14} />
              {t('detail.encrypted')}
            </span>
          </header>

          {isDocument && files}
          <TypeFields item={item} guard />
          {codeActions}
          {!isDocument && item.overview.type !== 'customTemplate' && files}

          {item.overview.tags && item.overview.tags.length > 0 && (
            <ul className={styles.tags} aria-label={t('fields.tags')}>
              {item.overview.tags.map((tag) => (
                <li key={tag}>{tag}</li>
              ))}
            </ul>
          )}

          {!trashed && <ItemPlaces item={item} editable={editable} />}
          <Meta item={item} vault={vault} />
          {!trashed && <ItemHistory item={item} editable={editable} />}
        </div>
        <AddCodeDialog item={item} open={codeDialog === 'add'} onClose={() => setCodeDialog(undefined)} />
        <LinkToLoginDialog item={item} open={codeDialog === 'link'} onClose={() => setCodeDialog(undefined)} />
        {sharing && (
          <>
            <ShareLinkDialog item={item} open={sharingLink} onClose={() => setSharingLink(false)} />
            <MoveCopyDialog item={item} mode={moveCopy} onClose={() => setMoveCopy(undefined)} />
          </>
        )}
      </article>
    </ItemUseProvider>
  );
}

/** `guard`: in the vault, where secrets that need confirming again (SSH private keys) ask first. */
export function TypeFields({ item, guard = false }: { item: Item; guard?: boolean }) {
  switch (item.overview.type) {
    case 'login':
    case 'password':
      return <LoginFields item={item} details={item.details as LoginDetails} live={guard} />;
    case 'card':
      return <CardFields details={item.details as CardDetails} />;
    case 'identity':
      return <IdentityFields details={item.details as IdentityDetails} />;
    case 'secureNote':
      return (
        <FieldList>
          <Field label={t('fields.note')} value={(item.details as SecureNoteDetails).notes || undefined} multiline secret />
        </FieldList>
      );
    case 'wifi':
      return <WifiFields item={item} live={guard} />;
    case 'environment':
      return <EnvironmentFields item={item} />;
    case 'sshKey':
      return <SshKeyFields item={item} guard={guard} />;
    case 'certificate':
      return <CertificateFields item={item} guard={guard} />;
    case 'key':
      return <KeyFields item={item} guard={guard} />;
    case 'bankAccount':
    case 'apiCredential':
    case 'softwareLicense':
    case 'idDocument':
    case 'cryptoWallet':
    case 'database':
      return <TableFields item={item} />;
    case 'custom':
      return <CustomFields details={item.details as CustomDetails} />;
    case 'customTemplate':
      return <TemplateFields details={item.details as CustomTemplateDetails} />;
    case 'document': {
      const notes = (item.details as DocumentDetails).notes;
      return notes ? (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={notes} multiline secret />
        </FieldList>
      ) : null;
    }
  }
}

function LoginFields({ item, details, live }: { item: Item; details: LoginDetails; live: boolean }) {
  // Each site once: other apps write one site several ways ('https://a.example/', '/login', 'www.').
  const urls = uniqueWebsites(item.overview.urls ?? [], item.overview.urlMatch);
  // Opening the website counts as using the login, as copying from it does.
  const recordUse = useRecordItemUse();
  return (
    <>
      {live && <ReusedPassword key={item.id} itemId={item.id} />}
      <FieldList>
        <Field label={t('fields.username')} value={details.username} secret={false} />
        <SecretField label={t('fields.password')} value={details.password} />
        <TotpField secret={details.totp} itemId={live ? item.id : undefined} />
        {urls.map((url, i) => {
          const mode = item.overview.urlMatch?.[url];
          return (
            <Field key={i} label={i === 0 ? t('fields.website') : t('fields.otherWebsite')} value={url} secret={false} what={t('fields.website')}>
              {mode === 'regex' ? (
                <bdi dir="ltr" className="mono">{url}</bdi>
              ) : (
                <a href={/^https?:\/\//i.test(url) ? url : `https://${url}`} target="_blank" rel="noopener noreferrer" onClick={recordUse}>
                  <bdi dir="ltr">{hostnameOf(url) ?? url}</bdi>
                  <Icon name="external" size={14} className={styles.external} />
                </a>
              )}
              {mode && mode !== DEFAULT_URL_MATCH_MODE && <small className={styles.matchMode}>{t(`editor.match.${mode}` as MessageKey)}</small>}
            </Field>
          );
        })}
        {details.httpRealm && <Field label={t('fields.httpRealm')} value={details.httpRealm} secret={false} copy={false} />}
      </FieldList>

      {details.passkeys && details.passkeys.length > 0 && (
        <FieldList title={t('detail.passkeys')}>
          {details.passkeys.map((pk, i) => (
            <Field key={i} label={pk.rpId} copy={false}>
              <span className={styles.passkey}>
                <Icon name="passkey" size={18} />
                <span>
                  <bdi>{pk.userName}</bdi>
                  <small>{t('detail.passkeySaved', { date: formatDate(pk.createdAt) })}</small>
                </span>
              </span>
            </Field>
          ))}
        </FieldList>
      )}

      {details.recovery && <RecoveryFields itemId={item.id} recovery={details.recovery} />}

      {details.customFields && details.customFields.length > 0 && (
        <FieldList title={t('detail.moreFields')}>
          {details.customFields.map((field, i) =>
            field.hidden ? <SecretField key={i} label={field.label} value={field.value} /> : <Field key={i} label={field.label} value={field.value} secret={false} />,
          )}
        </FieldList>
      )}

      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}

      {details.passwordHistory && details.passwordHistory.length > 0 && <PasswordHistory history={details.passwordHistory} />}
    </>
  );
}

/**
 * "Password used on 3 other logins", from Health's reused groups (the same password, whatever the
 * username). A group dismissed in Health isn't there, so it shows nothing. "See them" lists the
 * others, each opening its item, with "Change password" where the site has a change-password page.
 */
function ReusedPassword({ itemId }: { itemId: string }) {
  const report = useHealthReport();
  const [open, setOpen] = useState(false);
  const [changing, setChanging] = useState<HealthEntry>();
  const others = report?.reused.find((group) => group.some((entry) => entry.itemId === itemId))?.filter((entry) => entry.itemId !== itemId) ?? [];
  if (!others.length && !changing) return null;
  // The change-password address is on the login's first website, so its host names the site.
  const site = (entry: HealthEntry) => (entry.changePasswordUrl ? hostnameOf(entry.changePasswordUrl) : undefined);
  return (
    <>
      {others.length > 0 && (
        <Alert
          tone="warn"
          action={
            <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
              {t('detail.reuseSee')}
            </Button>
          }
        >
          <b>{t('detail.reuseTitle', { count: others.length })}</b> {t('detail.reuseBody')}
        </Alert>
      )}
      <Dialog open={open} onClose={() => setOpen(false)} size="md" title={t('detail.reuseList')} closeLabel={t('common.close')}>
        <ul className={healthStyles.rows}>
          {others.map((entry) => (
            <HealthRow
              key={entry.itemId}
              entry={{ ...entry, subtitle: [entry.subtitle, site(entry)].filter(Boolean).join(' · ') || undefined }}
              onChange={() => {
                setOpen(false);
                setChanging(entry);
              }}
            />
          ))}
        </ul>
      </Dialog>
      {changing && <ChangePasswordDialog entry={changing} onClose={() => setChanging(undefined)} />}
    </>
  );
}

/** A recovery email or phone, where it came from, and how many other logins it can reset (from the recovery map). */
function RecoveryContactField({ itemId, kind, value, source }: { itemId: string; kind: 'email' | 'phone'; value?: string; source?: RecoverySource }) {
  const report = useHealthReport();
  const identity = useItem(source?.kind === 'identity' ? source.itemId : undefined).item;
  if (!value) return null;
  const others = report?.recovery
    .find((contact) => contact.kind === kind && contact.logins.some((login) => login.itemId === itemId) && contact.value.toLowerCase() === value.trim().toLowerCase())
    ?.logins.filter((login) => login.itemId !== itemId).length;
  const link = source?.kind === 'alias' ? t('detail.linkedAlias', { provider: providerName(source.provider) }) : source?.kind === 'identity' && identity ? t('detail.linkedIdentity', { name: identity.overview.title }) : undefined;
  return (
    <Field label={kind === 'email' ? t('fields.recoveryEmail') : t('fields.recoveryPhone')} value={value} secret={false}>
      <span className={styles.contact}>
        <bdi dir="ltr">{value}</bdi>
        {link && (source?.kind === 'identity' ? <Link to={`/items/all/${source.itemId}`}>{link}</Link> : <small>{link}</small>)}
        {others !== undefined && others > 0 && <Link to="/health/recovery">{t('detail.alsoResets', { count: others })}</Link>}
      </span>
    </Field>
  );
}

function RecoveryFields({ itemId, recovery }: { itemId: string; recovery: NonNullable<LoginDetails['recovery']> }) {
  const [showCodes, setShowCodes] = useState(false);
  const codes = recovery.backupCodes ?? [];
  const left = codes.filter((c) => !c.used).length;
  return (
    <FieldList title={t('detail.recovery')}>
      {recovery.twoFactorMethod && <Field label={t('fields.twoFactorMethod')} value={t(`twoFactor.${recovery.twoFactorMethod}` as MessageKey)} copy={false} />}
      <RecoveryContactField itemId={itemId} kind="email" value={recovery.email} source={recovery.emailSource} />
      <RecoveryContactField itemId={itemId} kind="phone" value={recovery.phone} source={recovery.phoneSource} />
      {recovery.securityQuestions?.map((entry, i) => <SecretField key={i} label={entry.question} value={entry.answer} what={t('fields.securityAnswer')} />)}
      {codes.length > 0 && (
        <Field
          label={t('fields.backupCodes')}
          copy={false}
          actions={
            <Button variant="ghost" size="sm" aria-expanded={showCodes} onClick={() => setShowCodes((s) => !s)}>
              {showCodes ? t('common.hide') : t('common.show')}
            </Button>
          }
        >
          <span className={left <= 2 ? styles.lowCodes : undefined}>{t('detail.codesLeft', { left, count: codes.length })}</span>
          {showCodes && (
            <ul className={styles.codes}>
              {codes.map((c, i) => (
                <li key={i} className={c.used ? styles.used : undefined}>
                  <span className="mono">{c.code}</span>
                  <span className={styles.codeState}>{c.used ? t('detail.codeUsed') : t('detail.codeUnused')}</span>
                </li>
              ))}
            </ul>
          )}
        </Field>
      )}
    </FieldList>
  );
}

export function PasswordHistory({ history }: { history: NonNullable<LoginDetails['passwordHistory']> }) {
  const [open, setOpen] = useState(false);
  return (
    <section className={styles.history}>
      <button type="button" className={styles.historyToggle} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Icon name="history" size={16} />
        {t('detail.passwordHistory', { count: history.length })}
        <Icon name="chevronDown" size={16} className={open ? styles.flip : undefined} />
      </button>
      {open && (
        <FieldList>
          {history.map((entry, i) => (
            <SecretField key={i} label={t('detail.changedOn', { date: formatDate(entry.changedAt) })} value={entry.password} what={t('detail.oldPassword')} />
          ))}
        </FieldList>
      )}
    </section>
  );
}

function CardFields({ details }: { details: CardDetails }) {
  return (
    <>
      <div className={styles.card} aria-hidden="true">
        <span className={styles.chip} />
        <span className={['mono', styles.cardNumber].join(' ')}>•••• {details.number?.replace(/\s/g, '').slice(-4) ?? '••••'}</span>
        <span className={styles.cardMeta}>
          <span>{details.cardholder?.toUpperCase()}</span>
          <span>{details.expiry}</span>
        </span>
        {details.brand && <span className={styles.brand}>{details.brand}</span>}
      </div>
      <FieldList>
        <Field label={t('fields.cardholder')} value={details.cardholder} secret={false} />
        <SecretField label={t('fields.cardNumber')} value={details.number} format={formatCardNumber} />
        <Field label={t('fields.expiry')} value={details.expiry} secret={false} ltr />
        <SecretField label={t('fields.cvv')} value={details.cvv} />
        <SecretField label={t('fields.pin')} value={details.pin} />
        <Field label={t('fields.brand')} value={details.brand} copy={false} />
      </FieldList>
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}
    </>
  );
}

function IdentityFields({ details }: { details: IdentityDetails }) {
  const name = [details.firstName, details.lastName].filter(Boolean).join(' ');
  const a = details.address;
  const address = a ? [a.line1, a.line2, [a.city, a.region].filter(Boolean).join(', '), a.postalCode, a.country].filter(Boolean).join('\n') : '';
  return (
    <>
      <FieldList>
        <Field label={t('fields.fullName')} value={name || undefined} secret={false} />
        <Field label={t('fields.email')} value={details.email} secret={false} ltr />
        <Field label={t('fields.phone')} value={details.phone} secret={false} ltr />
        <Field label={t('fields.birthDate')} value={details.birthDate ? formatDate(details.birthDate) : undefined} secret={false} />
        <Field label={t('fields.address')} value={address || undefined} multiline secret={false} />
      </FieldList>
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}
    </>
  );
}

function Meta({ item, vault }: { item: Item; vault: Vault | undefined }) {
  const dates = itemDates(item);
  return (
    <footer className={styles.meta}>
      {vault && (
        <span>
          <Icon name={vault.type === 'family' ? 'home' : vault.type === 'shared' ? 'users' : 'vault'} size={14} />
          {vault.type !== 'personal' && vault.members ? t('detail.inSharedVault', { vault: vault.name, count: vault.members.length }) : t('detail.inVault', { vault: vault.name })}
        </span>
      )}
      <span>{t('detail.updated', { date: formatDate(dates.updatedAt, 'long') })}</span>
      <span>{t('detail.created', { date: formatDate(dates.createdAt) })}</span>
      {dates.passwordChangedAt && <span>{t('detail.passwordChanged', { date: formatDate(dates.passwordChangedAt) })}</span>}
      {dates.lastUsedAt && <span>{t('detail.lastUsed', { date: formatDate(dates.lastUsedAt) })}</span>}
    </footer>
  );
}
