import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { AliasMaker } from '../maskedEmail/MaskedEmailPage';
import { PageHeader } from '../PageHeader';
import { GeneratorPanel } from './GeneratorPanel';
import styles from './GeneratorPage.module.css';

/** `site`: the website a masked email is for, to start with (the extension passes the page the user was on). */
export function GeneratorPage({ site = '' }: { site?: string } = {}) {
  const masked = useService().maskedEmail;
  return (
    <div className={styles.page}>
      <PageHeader narrow title={t('generator.title')} subtitle={t('generator.subtitle')} />
      <div className={styles.body}>
        <GeneratorPanel />
        <p className={styles.note}>{t('generator.localNote')}</p>
        {masked && (
          <section className={styles.masked} aria-labelledby="masked-email-title">
            <h2 id="masked-email-title">{t('maskedEmail.make')}</h2>
            <AliasMaker key={site} initialSite={site} />
          </section>
        )}
      </div>
    </div>
  );
}
