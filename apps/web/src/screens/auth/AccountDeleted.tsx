import { Button } from '@octapass/ui';
import { useEffect } from 'react';
import { useNavigate } from 'react-router';
import { useExitTo } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { AuthLayout } from './AuthLayout';

export function AccountDeleted() {
  const navigate = useNavigate();
  const exitTo = useExitTo();

  useEffect(() => {
    exitTo.current = null;
  }, [exitTo]);

  return (
    <AuthLayout title={t('deleted.title')} subtitle={t('deleted.subtitle')}>
      <Button size="lg" block onClick={() => navigate('/welcome', { replace: true })}>
        {t('deleted.backToStart')}
      </Button>
    </AuthLayout>
  );
}
