// Registrable domains of sites known to offer authenticator-app (TOTP) or passkey sign-in, used by the
// health report's "missing two-factor" check. Hand-curated for milestone 1; P1 replaces it with a synced
// 2fa.directory snapshot. Only add a site after checking that it offers TOTP or passkeys, not just SMS.

export const TWO_FACTOR_DOMAINS: ReadonlySet<string> = new Set([
  // Developer tools and hosting
  'github.com', 'gitlab.com', 'bitbucket.org', 'atlassian.com', 'npmjs.com', 'pypi.org', 'docker.com',
  'heroku.com', 'digitalocean.com', 'linode.com', 'vercel.com', 'netlify.com', 'cloudflare.com',
  'hetzner.com', 'sentry.io', 'jetbrains.com', 'figma.com', 'notion.so', 'slack.com', 'zoom.us',
  'asana.com', 'okta.com',
  // Big platforms and email
  'google.com', 'microsoft.com', 'live.com', 'apple.com', 'icloud.com', 'amazon.com', 'yahoo.com',
  'proton.me', 'protonmail.com', 'fastmail.com', 'tuta.com', 'dropbox.com', 'box.com',
  'firefox.com',
  // Social
  'facebook.com', 'instagram.com', 'x.com', 'twitter.com', 'linkedin.com', 'reddit.com', 'discord.com',
  'twitch.tv', 'tiktok.com', 'snapchat.com', 'tumblr.com', 'pinterest.com',
  // Money and shopping
  'paypal.com', 'stripe.com', 'coinbase.com', 'kraken.com', 'binance.com', 'robinhood.com',
  'ebay.com', 'etsy.com', 'shopify.com', 'kickstarter.com', 'patreon.com',
  // Domains, sites and games
  'godaddy.com', 'namecheap.com', 'porkbun.com', 'wordpress.com', 'mailchimp.com', 'epicgames.com',
  'nintendo.com', 'playstation.com', 'ubisoft.com',
  // Password managers
  '1password.com', 'bitwarden.com', 'lastpass.com',
]);
