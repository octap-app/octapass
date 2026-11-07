// Installs the Safari fill-ins from ./compat for the service worker.

import { fillIdle, fixPortDelivery, type ConnectEvent, type Idle } from './compat';

fillIdle(chrome as { idle?: Idle });
fixPortDelivery(chrome.runtime.onConnect as unknown as ConnectEvent);
