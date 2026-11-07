// Safari's background entry. Imports run in order, so the fill-ins are in place before the shared
// service worker registers its listeners.

import './apis';
import '../background/index';
