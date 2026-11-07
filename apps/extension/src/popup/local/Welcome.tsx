import { Button } from '@octapass/ui';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import { useNavigate } from 'react-router';
import { tx } from '../../i18n';
import styles from './local.module.css';

/** First launch (plan 05): create an account (the default), sign in, or keep the vault on this device. */
export function Welcome() {
  const navigate = useNavigate();
  return (
    <AuthLayout title={tx('welcome.title')} subtitle={tx('welcome.subtitle')}>
      <div className={styles.stack}>
        <Button size="lg" block onClick={() => navigate('/signup')}>
          {tx('welcome.createAccount')}
        </Button>
        <Button size="lg" block variant="secondary" onClick={() => navigate('/signin')}>
          {tx('welcome.signIn')}
        </Button>
        <div className={styles.choice}>
          <Button size="lg" block variant="ghost" icon="lock" onClick={() => navigate('/local/new')}>
            {tx('welcome.local')}
          </Button>
          <p>{tx('welcome.localHelp')}</p>
        </div>
        <button type="button" className={styles.link} onClick={() => navigate('/local/restore')}>
          {tx('welcome.restore')}
        </button>
      </div>
    </AuthLayout>
  );
}
