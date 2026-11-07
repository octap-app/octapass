// Installs the Safari fill-ins from ./compat for the extension's pages. The Safari build loads it
// before each page's own script, so the page's first port already goes through it.

import { UI_PORT } from '../shared/rpc';
import { holdUntilAnswered, type Connect } from './compat';

holdUntilAnswered(chrome.runtime as unknown as Connect, UI_PORT);
