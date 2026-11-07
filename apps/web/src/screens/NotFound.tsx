import { Button, EmptyState } from '@octapass/ui';
import { useNavigate } from 'react-router';
import { t } from '../i18n';

export function NotFound() {
  const navigate = useNavigate();
  return <EmptyState icon="search" title={t('notFound.title')} action={<Button onClick={() => navigate('/items/all')}>{t('notFound.action')}</Button>}>{t('notFound.body')}</EmptyState>;
}
