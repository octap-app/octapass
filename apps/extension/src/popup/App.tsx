import { Toaster } from '@octapass/ui';
import type { VaultService } from '@octapass/vault-client';
import { RequireLocked, RequireSignedOut, RequireUnlocked } from '@octapass/web/src/app/guards';
import { ServiceProvider, useSession } from '@octapass/web/src/app/ServiceContext';
import { SettingsProvider } from '@octapass/web/src/app/settings';
import { IdentityGateProvider } from '@octapass/web/src/lib/identityGate';
import { SiteIconsProvider } from '@octapass/web/src/lib/siteIcons';
import { StayUnlockedProvider } from '@octapass/web/src/lib/stayUnlocked';
import { UsageRecorderContext } from '@octapass/web/src/lib/usage';
import { AccountDeleted } from '@octapass/web/src/screens/auth/AccountDeleted';
import { Lock } from '@octapass/web/src/screens/auth/Lock';
import { ResetPassword } from '@octapass/web/src/screens/auth/ResetPassword';
import { SignIn } from '@octapass/web/src/screens/auth/SignIn';
import { SignUp } from '@octapass/web/src/screens/auth/SignUp';
import { EmergencyPage } from '@octapass/web/src/screens/emergency/EmergencyPage';
import { EmergencyVaultPage } from '@octapass/web/src/screens/emergency/EmergencyVaultPage';
import { FilesPage } from '@octapass/web/src/screens/files/FilesPage';
import { HealthCheckPage } from '@octapass/web/src/screens/health/HealthCheckPage';
import { HealthPage } from '@octapass/web/src/screens/health/HealthPage';
import { RecoveryMapPage } from '@octapass/web/src/screens/health/RecoveryMapPage';
import { AccountOnly } from '@octapass/web/src/screens/local/NeedsSync';
import { MaskedEmailPage } from '@octapass/web/src/screens/maskedEmail/MaskedEmailPage';
import { NotFound } from '@octapass/web/src/screens/NotFound';
import { OrganisationPage } from '@octapass/web/src/screens/organisation/OrganisationPage';
import { SecurityLogPage } from '@octapass/web/src/screens/settings/SecurityLogPage';
import { SharingPage } from '@octapass/web/src/screens/sharing/SharingPage';
import { VaultMembersPage } from '@octapass/web/src/screens/sharing/VaultMembersPage';
import { ToolsPage } from '@octapass/web/src/screens/tools/ToolsPage';
import { ItemDetail } from '@octapass/web/src/screens/vault/ItemDetail';
import { ItemEditor } from '@octapass/web/src/screens/vault/ItemEditor';
import { ItemsPage, NoSelection } from '@octapass/web/src/screens/vault/ItemsPage';
import { useMemo } from 'react';
import { createMemoryRouter, Navigate, RouterProvider, type RouteObject } from 'react-router';
import { LOCAL_SERVER } from '../shared/local';
import { AppLayout } from './AppLayout';
import { DesktopUnlock } from './DesktopUnlock';
import { ExtensionProvider, type View } from './ExtensionContext';
import { FillAuthPrompt } from './FillAuthPrompt';
import { HttpAuthPrompt } from './HttpAuthPrompt';
import { CreateLocal } from './local/CreateLocal';
import { LocalLock } from './local/LocalLock';
import { RestoreBackup } from './local/RestoreBackup';
import { TurnOnSync } from './local/TurnOnSync';
import { Welcome } from './local/Welcome';
import { ScanScreen } from './ScanScreen';
import type { ExtensionApi } from './service';
import { SettingsScreen } from './SettingsScreen';
import { SiteGenerator, SitePage } from './SitePage';

/**
 * The app tab's routes: the web vault's, with the extension's own sign-in, local vault and settings
 * screens, "This site", and the prompts the background opens in small windows.
 */
export function appRoutes(): RouteObject[] {
  return [
    { path: '/welcome', element: <RequireSignedOut><Welcome /></RequireSignedOut> },
    { path: '/signin', element: <RequireSignedOut><SignIn /></RequireSignedOut> },
    { path: '/signup', element: <SignUp /> },
    { path: '/lock', element: <RequireLocked><LockScreen /></RequireLocked> },
    { path: '/reset', element: <ResetPassword /> },
    { path: '/local/new', element: <CreateLocal /> },
    { path: '/local/restore', element: <RequireSignedOut><RestoreBackup /></RequireSignedOut> },
    { path: '/local/sync', element: <RequireUnlocked><TurnOnSync /></RequireUnlocked> },
    { path: '/deleted', element: <AccountDeleted /> },
    // Opened by the background in its own window, for an HTTP sign-in prompt.
    { path: '/http-auth/:id', element: <HttpAuthPrompt /> },
    // Opened by the background when "Ask on every fill" is on.
    { path: '/auth/fill/:id', element: <FillAuthPrompt /> },
    {
      path: '/',
      element: <RequireUnlocked><AppLayout /></RequireUnlocked>,
      children: [
        { index: true, element: <Navigate to="/items/site" replace /> },
        {
          path: 'items/site',
          element: <SitePage />,
          children: [
            { index: true, element: <NoSelection /> },
            { path: ':itemId', element: <ItemDetail /> },
            { path: ':itemId/edit', element: <ItemEditor /> },
          ],
        },
        {
          path: 'items/:scope',
          element: <ItemsPage />,
          children: [
            { index: true, element: <NoSelection /> },
            { path: 'new', element: <ItemEditor /> },
            { path: ':itemId', element: <ItemDetail /> },
            { path: ':itemId/edit', element: <ItemEditor /> },
          ],
        },
        { path: 'generator', element: <SiteGenerator /> },
        { path: 'tools', element: <ToolsPage /> },
        { path: 'files', element: <FilesPage /> },
        { path: 'scan', element: <ScanScreen /> },
        // VaultLayout holds one Health report for these, so going between them doesn't check again.
        { path: 'health', element: <HealthPage /> },
        { path: 'health/recovery', element: <RecoveryMapPage /> },
        { path: 'health/:check', element: <HealthCheckPage /> },
        { path: 'masked-email', element: <AccountOnly><MaskedEmailPage /></AccountOnly> },
        { path: 'settings', element: <SettingsScreen /> },
        { path: 'settings/security-log', element: <SecurityLogPage /> },
        { path: 'sharing', element: <AccountOnly><SharingPage /></AccountOnly> },
        { path: 'sharing/vaults/:vaultId', element: <AccountOnly><VaultMembersPage /></AccountOnly> },
        { path: 'organisation', element: <AccountOnly><OrganisationPage /></AccountOnly> },
        { path: 'emergency', element: <AccountOnly><EmergencyPage /></AccountOnly> },
        { path: 'emergency/:contactId', element: <AccountOnly><EmergencyVaultPage /></AccountOnly> },
        { path: '*', element: <NotFound /> },
      ],
    },
  ];
}

/** A vault on this device only has no account to sign out of and no device unlock. */
function LockScreen() {
  if (useSession().serverUrl === LOCAL_SERVER) return <LocalLock />;
  return (
    <>
      <DesktopUnlock />
      <Lock />
    </>
  );
}

export interface PopupAppProps {
  service: VaultService;
  api: ExtensionApi;
  view: View;
  tabId?: number;
  initialPath?: string;
}

export function PopupApp({ service, api, view, tabId, initialPath = '/' }: PopupAppProps) {
  const router = createMemoryRouter(appRoutes(), { initialEntries: [initialPath] });
  // Uses are counted and saved in the service worker, with the fills from the inline menu.
  const recordUse = useMemo(() => (itemId: string) => void api.recordItemUse(itemId).catch(() => undefined), [api]);
  return (
    <ExtensionProvider value={{ api, view, ...(tabId !== undefined ? { tabId } : {}) }}>
      <ServiceProvider service={service}>
        <UsageRecorderContext.Provider value={recordUse}>
          <SettingsProvider>
            <SiteIconsProvider>
              <StayUnlockedProvider>
                <IdentityGateProvider>
                  <Toaster>
                    <RouterProvider router={router} />
                  </Toaster>
                </IdentityGateProvider>
              </StayUnlockedProvider>
            </SiteIconsProvider>
          </SettingsProvider>
        </UsageRecorderContext.Provider>
      </ServiceProvider>
    </ExtensionProvider>
  );
}
