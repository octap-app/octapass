import { ar } from './ar';
import { translator, type Leaves, type MessageVars } from './core';
import { en } from './en';

// The web vault's messages. The other apps use this catalog for the screens they share with the web
// vault, and a `translator` of their own for the rest.

export * from './core';

export type MessageKey = Leaves<typeof en>;

export const t: (key: MessageKey, vars?: MessageVars) => string = translator<typeof en>({ en, ar });
