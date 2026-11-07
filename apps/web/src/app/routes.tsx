import { createBrowserRouter, createMemoryRouter, Navigate, type RouteObject } from 'react-router';
import { AccountDeleted } from '../screens/auth/AccountDeleted';
import { Lock } from '../screens/auth/Lock';
import { ResetPassword } from '../screens/auth/ResetPassword';
import { SignIn } from '../screens/auth/SignIn';
import { SignUp } from '../screens/auth/SignUp';
import { FilesPage } from '../screens/files/FilesPage';
import { GeneratorPage } from '../screens/generator/GeneratorPage';
import { ToolsPage } from '../screens/tools/ToolsPage';
import { HealthCheckPage } from '../screens/health/HealthCheckPage';
import { HealthPage } from '../screens/health/HealthPage';
import { RecoveryMapPage } from '../screens/health/RecoveryMapPage';
import { MaskedEmailPage } from '../screens/maskedEmail/MaskedEmailPage';
import { OrganisationPage } from '../screens/organisation/OrganisationPage';
import { EmergencyPage } from '../screens/emergency/EmergencyPage';
import { EmergencyVaultPage } from '../screens/emergency/EmergencyVaultPage';
import { SecurityLogPage } from '../screens/settings/SecurityLogPage';
import { SettingsPage } from '../screens/settings/SettingsPage';
import { SharedLinkPage } from '../screens/sharing/SharedLinkPage';
import { SharingPage } from '../screens/sharing/SharingPage';
import { VaultMembersPage } from '../screens/sharing/VaultMembersPage';
import { ItemDetail } from '../screens/vault/ItemDetail';
import { ItemEditor } from '../screens/vault/ItemEditor';
import { ItemsPage, NoSelection } from '../screens/vault/ItemsPage';
import { VaultLayout } from '../screens/vault/VaultLayout';
import { NotFound } from '../screens/NotFound';
import { CreateLocal } from '../screens/local/CreateLocal';
import { AccountOnly } from '../screens/local/NeedsSync';
import { RestoreBackup } from '../screens/local/RestoreBackup';
import { TurnOnSync } from '../screens/local/TurnOnSync';
import { RequireLocked, RequireSignedOut, RequireUnlocked } from './guards';

export const routes: RouteObject[] = [
  { path: '/welcome', element: <RequireSignedOut><SignIn /></RequireSignedOut> },
  { path: '/signup', element: <SignUp /> },
  { path: '/reset', element: <ResetPassword /> },
  { path: '/lock', element: <RequireLocked><Lock /></RequireLocked> },
  { path: '/deleted', element: <AccountDeleted /> },
  // Only hosts with `service.local`; each of these sends anyone else back to the start.
  { path: '/local/new', element: <CreateLocal /> },
  { path: '/local/restore', element: <RestoreBackup /> },
  { path: '/local/sync', element: <RequireUnlocked><TurnOnSync /></RequireUnlocked> },
  // Share links open for anyone, signed in or not.
  { path: '/s/:linkId', element: <SharedLinkPage /> },
  {
    path: '/',
    element: <RequireUnlocked><VaultLayout /></RequireUnlocked>,
    children: [
      { index: true, element: <Navigate to="/items/all" replace /> },
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
      { path: 'generator', element: <GeneratorPage /> },
      { path: 'tools', element: <ToolsPage /> },
      { path: 'files', element: <FilesPage /> },
      { path: 'health', element: <HealthPage /> },
      { path: 'health/recovery', element: <RecoveryMapPage /> },
      // One check's list, such as /health/weak, and /health/dismissed.
      { path: 'health/:check', element: <HealthCheckPage /> },
      { path: 'masked-email', element: <AccountOnly><MaskedEmailPage /></AccountOnly> },
      { path: 'settings', element: <SettingsPage /> },
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

/** The app's router; the desktop app passes the routes with its own additions. */
export function createAppRouter(appRoutes: RouteObject[] = routes) {
  return createBrowserRouter(appRoutes);
}

export function createTestRouter(initialPath: string) {
  return createMemoryRouter(routes, { initialEntries: [initialPath] });
}
