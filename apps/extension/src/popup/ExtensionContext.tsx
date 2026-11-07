import { createContext, useContext, type ReactNode } from 'react';
import type { ExtensionApi } from './service';

/** Where this page is shown: the app tab, or a small prompt window the background opened. */
export type View = 'tab' | 'window';

interface ExtensionContextValue {
  api: ExtensionApi;
  view: View;
  /** The tab the app was opened from: "This site" starts with its page. */
  tabId?: number;
}

const ExtensionContext = createContext<ExtensionContextValue | null>(null);

export function ExtensionProvider({ value, children }: { value: ExtensionContextValue; children: ReactNode }) {
  return <ExtensionContext.Provider value={value}>{children}</ExtensionContext.Provider>;
}

export function useExtension(): ExtensionContextValue {
  const value = useContext(ExtensionContext);
  if (!value) throw new Error('useExtension must be used inside <ExtensionProvider>');
  return value;
}
