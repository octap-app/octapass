import { Button, Dialog, Spinner, useToast } from '@octapass/ui';
import type { Item, ItemVersion } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { TypeFields } from './ItemDetail';
import styles from './ItemDetail.module.css';

/**
 * An item's past versions: the last 10, encrypted like the item, read from the server only when
 * this is opened. A version is shown with the same fields as the item, so its secrets stay hidden
 * until revealed. Restoring is an ordinary edit, so it can be undone from the same list.
 */
export function ItemHistory({ item, editable }: { item: Item; editable: boolean }) {
  const service = useService();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [versions, setVersions] = useState<ItemVersion[]>();
  const [error, setError] = useState<string>();
  const [shown, setShown] = useState<number>();
  const [restoring, setRestoring] = useState<ItemVersion>();

  useEffect(() => {
    if (!open) return;
    let live = true;
    setVersions(undefined);
    setError(undefined);
    service.itemVersions!(item.id).then(
      (list) => live && setVersions(list),
      (e: unknown) => live && setError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, [service, item.id, item.revision, open]);

  if (!service.itemVersions) return null;

  async function restore() {
    await service.restoreItemVersion!(item.id, restoring!.revision);
    toast({ message: t('history.restored'), tone: 'success' });
    setRestoring(undefined);
    setShown(undefined);
    setOpen(false);
  }

  return (
    <>
      <Button variant="ghost" size="sm" icon="clock" onClick={() => setOpen(true)}>
        {t('history.action')}
      </Button>
      <Dialog open={open} onClose={() => setOpen(false)} closeLabel={t('common.close')} title={t('history.title')} size="md">
        <p className={styles.historyHelp}>{t('history.help')}</p>
        {error && <Alert>{error}</Alert>}
        {!versions && !error && <Spinner size={24} />}
        {versions?.length === 0 && <p className={styles.historyHelp}>{t('history.empty')}</p>}
        {versions && versions.length > 0 && (
          <ul className={styles.versions}>
            {versions.map((version) => (
              <li key={version.revision}>
                <div className={styles.versionRow}>
                  <span>
                    <strong>{formatDate(version.updatedAt, 'long')}</strong>
                    <small>
                      <bdi>{version.overview.title || t('detail.untitled')}</bdi>
                    </small>
                  </span>
                  <span className={styles.versionActions}>
                    <Button variant="ghost" size="sm" aria-expanded={shown === version.revision} onClick={() => setShown((s) => (s === version.revision ? undefined : version.revision))}>
                      {shown === version.revision ? t('common.hide') : t('common.show')}
                    </Button>
                    {editable && (
                      <Button variant="secondary" size="sm" onClick={() => setRestoring(version)}>
                        {t('history.restore')}
                      </Button>
                    )}
                  </span>
                </div>
                {shown === version.revision && <TypeFields item={{ ...item, overview: version.overview, details: version.details }} />}
              </li>
            ))}
          </ul>
        )}
      </Dialog>
      <ConfirmDialog
        open={Boolean(restoring)}
        title={t('history.confirmTitle')}
        confirmLabel={t('history.restore')}
        onConfirm={restore}
        onClose={() => setRestoring(undefined)}
      >
        {t('history.confirmBody', { date: restoring ? formatDate(restoring.updatedAt, 'long') : '' })}
      </ConfirmDialog>
    </>
  );
}
