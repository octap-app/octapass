import { Button, Segmented, Select, TextArea, TextField } from '@octapass/ui';
import type { CertificateDetails, ItemSummary } from '@octapass/vault-client';
import { useEffect, useMemo, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { PasswordInput } from '../../components/PasswordInput';
import { t, type MessageKey } from '../../i18n';
import { downloadBlob } from '../../lib/download';
import { useConfirmIdentity } from '../../lib/identityGate';
import { useItems } from '../../lib/useItems';
import { bytesOf, Card, FileButton, KEY_TYPES, Output, readFile, SaveToVault, ToolError, toolError, useTool } from './shared';
import styles from './Tools.module.css';

interface Problem {
  code: string;
  severity: 'error' | 'warning' | 'info';
}

interface CertificateInfo {
  subject: string;
  commonName?: string;
  issuer: string;
  notAfter: number;
  daysLeft: number;
  sans: { type: string; value: string }[];
  keyType: string;
  keyBits: number;
  curve?: string;
  signatureAlgorithm: string;
  isCa: boolean;
  sha256: string;
  spkiSha256: string;
  problems: Problem[];
}

interface Issued {
  certificate: string;
  chain?: string;
  privateKey: string;
  info: CertificateInfo;
}

interface Report {
  certificates?: CertificateInfo[];
  problems?: Problem[];
  csr?: { subject: string; sans: string[]; signatureValid: boolean; keyType: string; keyBits: number; curve?: string };
}

const keyLabel = (info: { keyType: string; keyBits: number; curve?: string }) => (info.curve ? `ECDSA ${info.curve}` : info.keyType === 'rsa' ? `RSA ${info.keyBits}` : info.keyType);
const names = (text: string) => text.split(/[\s,]+/).filter(Boolean);

function ProblemList({ problems }: { problems: Problem[] }) {
  return (
    <ul className={styles.list}>
      {problems.map((problem) => (
        <li key={problem.code} className={problem.severity === 'error' ? styles.bad : styles.note}>
          {t(`tools.certs.problems.${problem.code}` as MessageKey)}
        </li>
      ))}
    </ul>
  );
}

function CertificateCard({ info }: { info: CertificateInfo }) {
  return (
    <div className={styles.panel}>
      <dl className={styles.list}>
        <dt className={styles.note}>{t('tools.certs.subject')}</dt>
        <dd dir="ltr">{info.subject}</dd>
        <dt className={styles.note}>{t('tools.certs.issuer')}</dt>
        <dd dir="ltr">{info.issuer}</dd>
        {info.sans.length > 0 && (
          <>
            <dt className={styles.note}>{t('tools.certs.names')}</dt>
            <dd dir="ltr">{info.sans.map((san) => san.value).join(', ')}</dd>
          </>
        )}
        <dt className={styles.note}>{t('tools.certs.expires')}</dt>
        <dd>
          {new Date(info.notAfter * 1000).toLocaleDateString()} · {t('tools.certs.daysLeft', { count: info.daysLeft })}
        </dd>
        <dt className={styles.note}>{t('tools.certs.key')}</dt>
        <dd dir="ltr">
          {keyLabel(info)} · {info.signatureAlgorithm}
        </dd>
      </dl>
      <Output label="SHA-256" value={info.sha256} />
      <ProblemList problems={info.problems} />
    </div>
  );
}

/** A made certificate: its files, the gated private key, PKCS#12 and saving. */
function IssuedResult({ issued, source }: { issued: Issued; source: string }) {
  const { toolkit, run, busy, error } = useTool();
  const confirm = useConfirmIdentity();
  const [password, setPassword] = useState('');
  const [trustError, setTrustError] = useState<string>();
  const [trusted, setTrusted] = useState(false);
  const name = issued.info.commonName ?? 'certificate';

  async function p12() {
    if (!(await confirm({ reason: t('identityGate.body') }))) return;
    const file = await run<{ base64: string }>('cert.p12Write', { certificate: issued.certificate, chain: issued.chain, privateKey: issued.privateKey, password, friendlyName: name });
    if (file) downloadBlob(new Blob([bytesOf(file.base64)], { type: 'application/x-pkcs12' }), `${name}.p12`);
  }

  async function trust() {
    try {
      await toolkit.setCaTrust!(issued.certificate, true);
      setTrusted(true);
    } catch (e) {
      setTrustError(toolError(e));
    }
  }

  return (
    <>
      <CertificateCard info={issued.info} />
      <Output label={t('tools.certs.certificate')} value={issued.certificate} fileName={`${name}.pem`} />
      {issued.chain && <Output label={t('tools.certs.chain')} value={issued.chain} fileName={`${name}-chain.pem`} />}
      <Output label={t('tools.certs.privateKey')} value={issued.privateKey} fileName={`${name}-key.pem`} gated />
      <SaveToVault
        key={issued.info.sha256}
        defaultTitle={name}
        makeDraft={(title) => run('item.certificate', { title, certificate: issued.certificate, chain: issued.chain, privateKey: issued.privateKey, source })}
      />
      <div className={styles.row}>
        <PasswordInput label={t('tools.certs.p12Password')} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button variant="secondary" icon="download" busy={busy} disabled={!password} onClick={() => void p12()} style={{ flex: '0 0 auto' }}>
          {t('tools.certs.p12')}
        </Button>
      </div>
      <ToolError message={error} />
      {issued.info.isCa && toolkit.setCaTrust && (
        <>
          <p className={styles.note}>{t('tools.certs.trustNote')}</p>
          <Button variant="secondary" icon="shield" disabled={trusted} onClick={() => void trust()}>
            {t(trusted ? 'tools.certs.trusted' : 'tools.certs.trust')}
          </Button>
          <ToolError message={trustError} />
        </>
      )}
    </>
  );
}

type Mode = 'selfSigned' | 'ca' | 'issue' | 'csr';

function MakeCard() {
  const service = useService();
  const { run, busy, error, setError } = useTool();
  const [mode, setMode] = useState<Mode>('selfSigned');
  const [sans, setSans] = useState('localhost, 127.0.0.1');
  const [days, setDays] = useState('');
  const [keyType, setKeyType] = useState('p256');
  const [caName, setCaName] = useState('');
  const [caId, setCaId] = useState<string>();
  const [issued, setIssued] = useState<Issued>();
  const [csr, setCsr] = useState<{ csr: string; privateKey: string }>();
  const certificates = useItems(useMemo(() => ({ type: 'certificate' as const }), [])).items;

  async function make() {
    setIssued(undefined);
    setCsr(undefined);
    const parsed = Number.parseInt(days, 10);
    const common = { keyType, ...(Number.isNaN(parsed) ? {} : { days: parsed }) };
    if (mode === 'selfSigned') setIssued(await run<Issued>('cert.selfSigned', { ...common, sans: names(sans) }));
    else if (mode === 'ca') setIssued(await run<Issued>('cert.caCreate', { ...common, subject: { commonName: caName || undefined } }));
    else if (mode === 'csr') setCsr(await run('cert.csr', { keyType, sans: names(sans) }));
    else {
      const id = caId ?? certificates?.[0]?.id;
      if (!id) {
        setError(t('tools.certs.noCa'));
        return;
      }
      const ca = (await service.getItem(id)).details as CertificateDetails;
      if (!ca.privateKey || !ca.certificate) {
        setError(t('tools.certs.noCa'));
        return;
      }
      setIssued(await run<Issued>('cert.issue', { ...common, sans: names(sans), caCertificate: ca.certificate, caKey: ca.privateKey }));
    }
  }

  return (
    <Card title={t('tools.certs.make')}>
      <Select
        label={t('tools.certs.what')}
        value={mode}
        onChange={(e) => setMode(e.target.value as Mode)}
        options={(['selfSigned', 'ca', 'issue', 'csr'] as const).map((value) => ({ value, label: t(`tools.certs.modes.${value}` as MessageKey) }))}
      />
      {mode === 'ca' ? (
        <>
          <TextField label={t('tools.certs.caName')} placeholder="Octa Pass Local CA" value={caName} onChange={(e) => setCaName(e.target.value)} />
          <p className={styles.note}>{t('tools.certs.caNote')}</p>
        </>
      ) : (
        <TextArea label={t('tools.certs.sans')} hint={t('tools.certs.sansHint')} mono dir="ltr" spellCheck={false} value={sans} onChange={(e) => setSans(e.target.value)} />
      )}
      {mode === 'issue' && (
        <Select label={t('tools.certs.ca')} value={caId ?? certificates?.[0]?.id ?? ''} onChange={(e) => setCaId(e.target.value)} options={(certificates ?? []).map((item: ItemSummary) => ({ value: item.id, label: item.title }))} />
      )}
      <div className={styles.row}>
        <Select label={t('tools.certs.keyType')} value={keyType} onChange={(e) => setKeyType(e.target.value)} options={KEY_TYPES} />
        {mode !== 'csr' && <TextField label={t('tools.certs.days')} inputMode="numeric" placeholder={mode === 'ca' ? '3650' : '365'} value={days} onChange={(e) => setDays(e.target.value)} />}
      </div>
      <div className={styles.actions}>
        <Button icon="shield" busy={busy} onClick={() => void make()}>
          {t('tools.certs.makeAction')}
        </Button>
      </div>
      <ToolError message={error} />
      {issued && <IssuedResult issued={issued} source={mode === 'selfSigned' ? 'selfSigned' : 'localCa'} />}
      {csr && (
        <>
          <Output label={t('tools.certs.csr')} value={csr.csr} fileName="request.csr" />
          <Output label={t('tools.certs.privateKey')} value={csr.privateKey} fileName="request-key.pem" gated />
        </>
      )}
    </Card>
  );
}

function ReadCard() {
  const { toolkit, run, busy, error, setError } = useTool();
  const [text, setText] = useState('');
  const [host, setHost] = useState('');
  const [report, setReport] = useState<Report>();
  const [fetching, setFetching] = useState(false);
  const [connection, setConnection] = useState<string>();

  async function read() {
    setConnection(undefined);
    setReport(await run<Report>('cert.read', { text, host: host.trim() || undefined }));
  }

  async function fetchHost() {
    setFetching(true);
    setError(undefined);
    setReport(undefined);
    try {
      const probe = await toolkit.fetchHostCertificates!(host.trim());
      setText(probe.pem);
      setConnection(probe.trusted ? t('tools.certs.publiclyTrusted') : t('tools.certs.notPubliclyTrusted', { reason: probe.trustError ?? '' }));
      setReport(await run<Report>('cert.read', { text: probe.pem, host: probe.host }));
    } catch (e) {
      setError(toolError(e));
    } finally {
      setFetching(false);
    }
  }

  return (
    <Card title={t('tools.certs.read')}>
      <TextArea label={t('tools.certs.pem')} mono dir="ltr" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
      <FileButton label={t('tools.certs.file')} onFile={(file) => void readFile(file).then(setText)} />
      <TextField label={t('tools.certs.host')} hint={toolkit.fetchHostCertificates ? t('tools.certs.hostHint') : t('tools.certs.hostWebHint')} placeholder="example.com:443" dir="ltr" value={host} onChange={(e) => setHost(e.target.value)} />
      <div className={styles.actions}>
        <Button busy={busy} disabled={!text.trim()} onClick={() => void read()}>
          {t('tools.certs.readAction')}
        </Button>
        {toolkit.fetchHostCertificates && (
          <Button variant="secondary" icon="link" busy={fetching} disabled={!host.trim()} onClick={() => void fetchHost()}>
            {t('tools.certs.fetchAction')}
          </Button>
        )}
      </div>
      <ToolError message={error} />
      {connection && <p className={styles.note}>{connection}</p>}
      {report?.csr && (
        <>
          <p dir="ltr">{report.csr.subject}</p>
          <p dir="ltr">{report.csr.sans.join(', ')}</p>
          <p dir="ltr">{keyLabel(report.csr)}</p>
          <p className={report.csr.signatureValid ? styles.ok : styles.bad}>{t(report.csr.signatureValid ? 'tools.certs.csrValid' : 'tools.certs.csrInvalid')}</p>
        </>
      )}
      {report?.certificates?.map((info) => <CertificateCard key={info.sha256} info={info} />)}
      {report?.problems && <ProblemList problems={report.problems} />}
    </Card>
  );
}

interface Due {
  id: string;
  title: string;
  state: string;
  daysLeft: number;
}

/** Renewal reminders: saved certificates that are in their renewal window or past it. */
function Reminders() {
  const service = useService();
  const { toolkit } = useTool();
  const certificates = useItems(useMemo(() => ({ type: 'certificate' as const }), [])).items;
  const [due, setDue] = useState<Due[]>([]);

  useEffect(() => {
    let live = true;
    void (async () => {
      const found: Due[] = [];
      for (const summary of certificates ?? []) {
        const details = (await service.getItem(summary.id)).details as CertificateDetails;
        if (!details.notBefore || !details.notAfter) continue;
        const renewal = await toolkit.run<{ state: string; daysLeft: number }>('cert.renewal', {
          notBefore: Math.floor(Date.parse(details.notBefore) / 1000),
          notAfter: Math.floor(Date.parse(details.notAfter) / 1000),
        });
        if (renewal.state !== 'ok') found.push({ id: summary.id, title: summary.title, ...renewal });
      }
      if (live) setDue(found);
    })().catch(() => undefined);
    return () => {
      live = false;
    };
  }, [certificates, service, toolkit]);

  if (due.length === 0) return null;
  return (
    <Card title={t('tools.certs.renewals')}>
      <ul className={styles.list}>
        {due.map((entry) => (
          <li key={entry.id} className={entry.state === 'expired' ? styles.bad : undefined}>
            <bdi>{entry.title}</bdi>: {entry.state === 'expired' ? t('tools.certs.expired') : t('tools.certs.daysLeft', { count: entry.daysLeft })}
          </li>
        ))}
      </ul>
      <p className={styles.note}>{t('tools.certs.renewNote')}</p>
    </Card>
  );
}

export function CertificatesPanel() {
  const [mode, setMode] = useState<'make' | 'read'>('make');
  return (
    <div className={styles.panel}>
      <Reminders />
      <Segmented
        label={t('tools.panels.certificates')}
        value={mode}
        onChange={setMode}
        block
        options={[
          { value: 'make', label: t('tools.certs.make') },
          { value: 'read', label: t('tools.certs.read') },
        ]}
      />
      {mode === 'make' ? <MakeCard /> : <ReadCard />}
    </div>
  );
}
