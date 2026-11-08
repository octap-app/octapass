interface ImportMetaEnv {
  /** The server behind the "Octa Pass" choice on the sign-in screens. */
  readonly VITE_SERVER_URL?: string;
}

/** The browser this build is for (`chrome`, `firefox` or `safari`), set by vite.config.ts. Unset in tests. */
declare const __OCTAPASS_TARGET__: string | undefined;
