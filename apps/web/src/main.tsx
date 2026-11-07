import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/noto-sans-arabic/wght.css';
import '@fontsource/monaspace-neon/400.css';
import '@fontsource/monaspace-neon/600.css';
import '@octapass/ui/styles.css';
import './app/app.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import { createVaultService } from './app/service';

const service = await createVaultService();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App service={service} />
  </StrictMode>,
);
