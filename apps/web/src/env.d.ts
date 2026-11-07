interface ImportMetaEnv {
  /** `remote` (default) or `mock`. */
  readonly VITE_VAULT_BACKEND?: string;
  /** The server behind the "Octa Pass" choice on the sign-in screens; `same-origin` for the server serving the page. */
  readonly VITE_SERVER_URL?: string;
}
