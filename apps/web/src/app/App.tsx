import { Toaster } from '@octapass/ui';
import type { VaultService } from '@octapass/vault-client';
import { RouterProvider } from 'react-router';
import { createAppRouter } from './routes';
import { ServiceProvider } from './ServiceContext';
import { SettingsProvider } from './settings';
import { SiteIconsProvider } from '../lib/siteIcons';
import { IdentityGateProvider } from '../lib/identityGate';
import { StayUnlockedProvider } from '../lib/stayUnlocked';

export function App({ service, router = createAppRouter() }: { service: VaultService; router?: ReturnType<typeof createAppRouter> }) {
  return (
    <ServiceProvider service={service}>
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
    </ServiceProvider>
  );
}
