//! Transactional email over SMTP.

use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// The server's host name, named in each email's footer.
    server: String,
}

/// The logo in every email, attached inline: a remote image would tell its host who opened what.
const LOGO: &[u8] = include_bytes!("../assets/email-logo.png");
const LOGO_CID: &str = "logo@octapass";

pub enum Email {
    VerificationCode(String),
    /// Sent instead of a code when someone signs up with an email that already
    /// has an account, so the sign-up response can't reveal which emails exist.
    AccountExists,
    AccountDeleted,
    FamilyInvite {
        organiser: String,
    },
    /// Names only who invited them: an organisation's name is free text, and this can reach
    /// addresses with no account.
    OrgInvite {
        inviter: String,
    },
    /// To someone the organisation's identity provider added (SCIM): an invite with no inviter.
    OrgProvisioned,
    /// To a member an admin removed.
    OrgRemoved,
    /// To the contact a grantor chose.
    EmergencyContactAdded {
        grantor: String,
    },
    /// To the grantor, when the contact asks, then daily while the request waits.
    EmergencyAccessRequested {
        contact: String,
        releases_on: String,
        reminder: bool,
    },
    /// To the contact.
    EmergencyAccessDenied {
        grantor: String,
    },
    /// To the contact, and (`to_grantor`) to the grantor.
    EmergencyAccessReleased {
        other: String,
        to_grantor: bool,
    },
    TwoStepEnabled,
    TwoStepDisabled,
    /// A sign-in used a recovery code; `left` remain.
    RecoveryCodeUsed {
        left: i64,
    },
    /// Too many wrong second-step codes: someone has the master password and Secret Key.
    TwoStepLocked,
    /// The code that starts a master password reset with the recovery code.
    PasswordResetCode(String),
    /// A new master password was set while signed in.
    PasswordChanged,
    SecretKeyRotated,
    /// To the grantor: `contact` set a new master password and Secret Key for the account.
    EmergencyTakeover {
        contact: String,
    },
    /// The master password was reset with the recovery code.
    PasswordReset,
    /// A device that isn't trusted yet signed in. `at` is from [`readable_time`].
    NewSignIn {
        device: String,
        platform: String,
        at: String,
    },
}

/// What one email says, written once and rendered as plain text and as HTML.
pub struct Content {
    pub subject: String,
    /// A short label above the heading: what the email is about.
    pub topic: &'static str,
    pub heading: String,
    /// A code to type in, shown large.
    pub code: Option<String>,
    pub body: Vec<String>,
    /// Facts shown as a small table, like a new device's name and the time.
    pub details: Vec<(&'static str, String)>,
    /// What to do if the reader didn't do this, set apart from the rest.
    pub if_not_you: Option<String>,
}

const TOPIC_ACCOUNT: &str = "Your account";
const TOPIC_SECURITY: &str = "Security";
const TOPIC_TWO_STEP: &str = "Two-step sign-in";
const TOPIC_FAMILY: &str = "Family";
const TOPIC_ORG: &str = "Organisation";
const TOPIC_EMERGENCY: &str = "Emergency access";

/// The line at the end of every email, in both parts.
const FOOTER: &str = "Octa Pass emails never contain sign-in links and never ask for your master \
                      password, Secret Key or recovery code.";

impl Email {
    /// Subject and plain-text body.
    pub fn render(&self) -> (String, String) {
        let content = self.content();
        let text = content.text();
        (content.subject, text)
    }

    pub fn content(&self) -> Content {
        let c = |subject: String, topic, heading: String, body: Vec<String>| Content {
            subject,
            topic,
            heading,
            code: None,
            body,
            details: Vec::new(),
            if_not_you: None,
        };
        match self {
            Email::VerificationCode(code) => Content {
                code: Some(code.clone()),
                ..c(
                    format!("Your Octa Pass verification code: {code}"),
                    TOPIC_ACCOUNT,
                    "Confirm your email".to_owned(),
                    vec![
                        format!("Your Octa Pass verification code is {code}."),
                        "It expires in 15 minutes. If you didn't try to create an Octa Pass account, ignore this email.".to_owned(),
                    ],
                )
            },
            Email::AccountExists => Content {
                if_not_you: Some("If it wasn't you, you can ignore this email: nothing changed.".to_owned()),
                ..c(
                    "Someone tried to create an Octa Pass account with your email".to_owned(),
                    TOPIC_ACCOUNT,
                    "You already have an account".to_owned(),
                    vec![
                        "Someone tried to create an Octa Pass account with this email address, but it already has one.".to_owned(),
                        "If it was you, sign in instead.".to_owned(),
                    ],
                )
            },
            Email::AccountDeleted => c(
                "Your Octa Pass account was deleted".to_owned(),
                TOPIC_ACCOUNT,
                "Your account was deleted".to_owned(),
                vec![
                    "Your Octa Pass account and everything in it were permanently deleted.".to_owned(),
                    "Your devices were signed out, and this email address can be used for a new account. \
                     Encrypted server backups that still contain your data are rotated out within 30 days."
                        .to_owned(),
                ],
            ),
            Email::FamilyInvite { organiser } => c(
                format!("{organiser} invited you to their Octa Pass family"),
                TOPIC_FAMILY,
                format!("{organiser} invited you to their family"),
                vec![
                    format!("{organiser} invited you to join their family on Octa Pass. Open the app to accept or decline."),
                    "Family members share a Family vault and keep their own private vaults.".to_owned(),
                ],
            ),
            Email::OrgInvite { inviter } => c(
                format!("{inviter} invited you to an organisation on Octa Pass"),
                TOPIC_ORG,
                format!("{inviter} invited you to their organisation"),
                vec![
                    format!(
                        "{inviter} invited you to join their organisation on Octa Pass. Sign in with this email \
                         address to see the invitation, and the rules that come with it, before you accept. \
                         If you don't have an account yet, create one with this address."
                    ),
                    "Your personal vault stays private: nobody in the organisation can read it. The invitation \
                     lasts 14 days. If you weren't expecting it, you can ignore this email."
                        .to_owned(),
                ],
            ),
            Email::OrgProvisioned => c(
                "You're invited to an organisation on Octa Pass".to_owned(),
                TOPIC_ORG,
                "Your organisation invited you".to_owned(),
                vec![
                    "Your organisation's identity provider added you to its organisation on Octa Pass. Sign in \
                     with this email address to see the invitation, and the rules that come with it, before \
                     you accept. If you don't have an account yet, create one with this address."
                        .to_owned(),
                    "Your personal vault stays private: nobody in the organisation can read it. The invitation \
                     lasts 14 days. If you weren't expecting it, you can ignore this email."
                        .to_owned(),
                ],
            ),
            Email::OrgRemoved => c(
                "You were removed from an organisation on Octa Pass".to_owned(),
                TOPIC_ORG,
                "You were removed from an organisation".to_owned(),
                vec![
                    "An administrator removed you from your organisation on Octa Pass. Its vaults are no longer \
                     available to you. Your account and personal vault are unchanged."
                        .to_owned(),
                ],
            ),
            Email::EmergencyContactAdded { grantor } => c(
                format!("{grantor} chose you as an emergency contact"),
                TOPIC_EMERGENCY,
                format!("{grantor} chose you as their emergency contact"),
                vec![
                    format!("{grantor} chose you as their emergency contact on Octa Pass."),
                    "If something happens to them, you can request access from the app. They get a waiting \
                     period to deny the request; after it, you can open what they shared with you."
                        .to_owned(),
                ],
            ),
            Email::EmergencyAccessRequested {
                contact,
                releases_on,
                reminder,
            } => Content {
                details: vec![("Released on", releases_on.clone())],
                if_not_you: Some(
                    "If you didn't expect this, deny the request in the app under Emergency access.".to_owned(),
                ),
                ..c(
                    if *reminder {
                        format!("Reminder: {contact} is waiting for emergency access")
                    } else {
                        format!("{contact} requested emergency access to your Octa Pass account")
                    },
                    TOPIC_EMERGENCY,
                    format!("{contact} asked for emergency access"),
                    vec![format!(
                        "{contact} requested emergency access to your Octa Pass account. Unless you deny it, \
                         access is released on {releases_on}."
                    )],
                )
            },
            Email::EmergencyAccessDenied { grantor } => c(
                format!("{grantor} denied your emergency access request"),
                TOPIC_EMERGENCY,
                "Your request was denied".to_owned(),
                vec![format!(
                    "{grantor} denied your emergency access request on Octa Pass. Nothing was released."
                )],
            ),
            Email::EmergencyAccessReleased { other, to_grantor } => {
                if *to_grantor {
                    Content {
                        if_not_you: Some(
                            "If that's wrong, deny it in the app under Emergency access, then change your \
                             master password and rotate any vaults you shared."
                                .to_owned(),
                        ),
                        ..c(
                            format!("Emergency access was released to {other}"),
                            TOPIC_EMERGENCY,
                            format!("Emergency access was released to {other}"),
                            vec![format!(
                                "Emergency access to your Octa Pass account was released to {other}."
                            )],
                        )
                    }
                } else {
                    c(
                        format!("Emergency access to {other}'s Octa Pass account is ready"),
                        TOPIC_EMERGENCY,
                        format!("You can now open {other}'s vault"),
                        vec![format!(
                            "Emergency access to {other}'s Octa Pass account was released. Open the app to view it."
                        )],
                    )
                }
            }
            Email::TwoStepEnabled => Content {
                if_not_you: Some("If you didn't do this, sign in and check Settings, then your security log.".to_owned()),
                ..c(
                    "Two-step sign-in turned on".to_owned(),
                    TOPIC_TWO_STEP,
                    "Two-step sign-in is on".to_owned(),
                    vec![
                        "Two-step sign-in is now on for your Octa Pass account. Signing in on a new device asks \
                         for a code from your authenticator app, a security key or a recovery code. Devices \
                         already signed in keep working."
                            .to_owned(),
                    ],
                )
            },
            Email::TwoStepDisabled => Content {
                if_not_you: Some(
                    "If you didn't do this, sign in, turn it back on in Settings and sign out devices you don't know."
                        .to_owned(),
                ),
                ..c(
                    "Two-step sign-in turned off".to_owned(),
                    TOPIC_TWO_STEP,
                    "Two-step sign-in is off".to_owned(),
                    vec![
                        "Two-step sign-in is now off for your Octa Pass account. New devices only need your \
                         master password and Secret Key."
                            .to_owned(),
                    ],
                )
            },
            Email::RecoveryCodeUsed { left } => Content {
                details: vec![("Recovery codes left", left.to_string())],
                if_not_you: Some(
                    "If it wasn't you, sign out that device in Settings and make new recovery codes.".to_owned(),
                ),
                ..c(
                    "A recovery code was used to sign in to Octa Pass".to_owned(),
                    TOPIC_TWO_STEP,
                    "A recovery code was used".to_owned(),
                    vec![format!(
                        "A new device signed in to your Octa Pass account with one of your two-step recovery \
                         codes. You have {left} left; you can make new ones in Settings."
                    )],
                )
            },
            Email::TwoStepLocked => Content {
                if_not_you: Some(
                    "If it wasn't you, your master password and Secret Key may be known to someone else.".to_owned(),
                ),
                ..c(
                    "Several wrong two-step codes for your Octa Pass account".to_owned(),
                    TOPIC_SECURITY,
                    "Several wrong two-step codes".to_owned(),
                    vec![
                        "Someone entered your master password and Secret Key, then several wrong two-step \
                         codes. Two-step sign-in is paused for a few minutes."
                            .to_owned(),
                    ],
                )
            },
            Email::PasswordResetCode(code) => Content {
                code: Some(code.clone()),
                if_not_you: Some(
                    "If you didn't ask to reset your master password, ignore this email: nothing changed.".to_owned(),
                ),
                ..c(
                    format!("Your Octa Pass reset code: {code}"),
                    TOPIC_SECURITY,
                    "Reset your master password".to_owned(),
                    vec![
                        format!("Your code to reset your Octa Pass master password is {code}."),
                        "It expires in 15 minutes. You'll also need your recovery code from your Recovery Kit."
                            .to_owned(),
                    ],
                )
            },
            Email::PasswordChanged => Content {
                if_not_you: Some(
                    "If you didn't do this, someone knows your master password and Secret Key. Reset your \
                     master password with the recovery code from your Recovery Kit."
                        .to_owned(),
                ),
                ..c(
                    "Your Octa Pass master password was changed".to_owned(),
                    TOPIC_SECURITY,
                    "Your master password was changed".to_owned(),
                    vec![
                        "The master password of your Octa Pass account was changed. Your other devices were \
                         signed out: sign in on them with the new master password."
                            .to_owned(),
                    ],
                )
            },
            Email::SecretKeyRotated => Content {
                if_not_you: Some(
                    "If you didn't do this, someone knows your master password and Secret Key. Reset your \
                     master password with the recovery code from your Recovery Kit."
                        .to_owned(),
                ),
                ..c(
                    "Your Octa Pass Secret Key was changed".to_owned(),
                    TOPIC_SECURITY,
                    "Your Secret Key was changed".to_owned(),
                    vec![
                        "The Secret Key of your Octa Pass account was changed. Your other devices were signed \
                         out: sign in on them with the new Secret Key from your new Recovery Kit."
                            .to_owned(),
                    ],
                )
            },
            Email::EmergencyTakeover { contact } => Content {
                if_not_you: Some(format!(
                    "To get back in, ask {contact} for the new Recovery Kit. If you didn't expect this, contact \
                     them right away and change the passwords stored in your vault."
                )),
                ..c(
                    format!("{contact} took over your Octa Pass account"),
                    TOPIC_EMERGENCY,
                    format!("{contact} took over your account"),
                    vec![format!(
                        "{contact} used the emergency access you gave them to set a new master password and \
                         Secret Key for your Octa Pass account. Every device was signed out, the old recovery \
                         code stopped working, and two-step sign-in was turned off."
                    )],
                )
            },
            Email::PasswordReset => Content {
                if_not_you: Some(
                    "If you didn't do this, someone had your recovery code and access to this email address. \
                     Reset your master password again if you still have the new Recovery Kit, then secure this \
                     email account."
                        .to_owned(),
                ),
                ..c(
                    "Your Octa Pass master password was reset".to_owned(),
                    TOPIC_SECURITY,
                    "Your master password was reset".to_owned(),
                    vec![
                        "The master password of your Octa Pass account was reset with your recovery code, and \
                         the recovery code was replaced. Every device was signed out: sign in with the new \
                         master password."
                            .to_owned(),
                    ],
                )
            },
            Email::NewSignIn {
                device,
                platform,
                at,
            } => Content {
                details: vec![("Device", format!("\"{device}\" ({platform})")), ("Time", at.clone())],
                if_not_you: Some(
                    "If it was you, there's nothing to do. If it wasn't, open Octa Pass on a device you trust, \
                     sign that device out under Settings > Devices, then change your master password. \
                     Whoever it was knew your master password and Secret Key."
                        .to_owned(),
                ),
                ..c(
                    "New sign-in to your Octa Pass account".to_owned(),
                    TOPIC_SECURITY,
                    "A new device signed in".to_owned(),
                    vec!["A new device signed in to your Octa Pass account.".to_owned()],
                )
            },
        }
    }
}

impl Content {
    /// The plain-text part: the body, the details, what to do if it wasn't you, and the footer.
    pub fn text(&self) -> String {
        let mut parts = self.body.clone();
        if !self.details.is_empty() {
            parts.push(
                self.details
                    .iter()
                    .map(|(label, value)| format!("{label}: {value}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        parts.extend(self.if_not_you.clone());
        parts.push(format!("--\n{FOOTER}"));
        parts.join("\n\n")
    }

    /// The HTML part. Tables and inline styles, so it holds together in Outlook and Gmail; no
    /// remote images or links, so opening it tells nobody anything. `logo_cid` is the inline
    /// logo's Content-ID and `server` names the server that sent it.
    pub fn html(&self, logo_cid: &str, server: &str) -> String {
        let e = escape;
        let preheader = e(self.body.first().map_or("", String::as_str));
        let code = self.code.as_ref().map_or(String::new(), |code| {
            format!(
                r#"<tr><td style="padding:4px 0 24px"><div class="tile ink" style="background:#F2F3F7;border-radius:14px;padding:20px 24px;text-align:center;font-family:'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;font-size:34px;font-weight:600;letter-spacing:6px;color:#0B1220">{}</div></td></tr>"#,
                e(code)
            )
        });
        let body: String = self
            .body
            .iter()
            .map(|p| format!(r#"<p style="margin:0 0 16px">{}</p>"#, e(p)))
            .collect();
        let details = if self.details.is_empty() {
            String::new()
        } else {
            let rows: String = self
                .details
                .iter()
                .enumerate()
                .map(|(i, (label, value))| {
                    let border = if i == 0 { "" } else { "border-top:1px solid #E3E5EC;" };
                    format!(
                        r#"<tr><td class="mist line" style="{border}padding:10px 16px;color:#5E6576;font-size:14px;width:40%">{}</td><td class="line" style="{border}padding:10px 16px;font-size:14px;font-weight:600">{}</td></tr>"#,
                        e(label),
                        e(value)
                    )
                })
                .collect();
            format!(
                r#"<tr><td style="padding:4px 0 20px"><table role="presentation" class="tile" width="100%" cellpadding="0" cellspacing="0" style="background:#F2F3F7;border-radius:12px;border-collapse:separate">{rows}</table></td></tr>"#
            )
        };
        let if_not_you = self.if_not_you.as_ref().map_or(String::new(), |text| {
            format!(
                r#"<tr><td style="padding:4px 0 8px"><div class="note" style="border-left:3px solid #2456F0;background:#EEF2FE;border-radius:0 10px 10px 0;padding:14px 18px;font-size:15px;line-height:1.5">{}</div></td></tr>"#,
                e(text)
            )
        });
        format!(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark"><title>{title}</title>
<style>
body{{margin:0;padding:0;-webkit-text-size-adjust:100%}}
@media (max-width:620px){{.card{{padding:28px 22px!important}}.outer{{padding:16px 10px!important}}}}
@media (prefers-color-scheme:dark){{
.page{{background:#000000!important}}
.card{{background:#0D1017!important;border-color:#232838!important;border-top-color:#5C86FF!important}}
.ink,.card td,.card p,.card .ink{{color:#F5F6F8!important}}
.mist,.mist p,.card .mist{{color:#9BA3B4!important}}
.tile,.card .tile{{background:#141824!important}}.card .line{{border-color:#232838!important}}
.card .note{{background:#141C33!important;border-color:#5C86FF!important}}.card .topic{{color:#4FE0A8!important}}
}}
</style></head>
<body class="page" style="margin:0;padding:0;background:#F2F3F7">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">{preheader}</div>
<table role="presentation" class="page" width="100%" cellpadding="0" cellspacing="0" style="background:#F2F3F7">
<tr><td class="outer" align="center" style="padding:40px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
<tr><td style="padding:0 4px 20px"><table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td style="vertical-align:middle"><img src="cid:{logo_cid}" width="32" height="32" alt="" style="display:block;border:0;border-radius:8px"></td>
<td class="ink" style="vertical-align:middle;padding-left:10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:19px;letter-spacing:-0.3px;color:#0B1220"><span style="font-weight:400">Octa&nbsp;</span><span style="font-weight:800">Pass</span></td>
</tr></table></td></tr>
<tr><td class="card" style="background:#FFFFFF;border:1px solid #E3E5EC;border-top:4px solid #2456F0;border-radius:18px;padding:36px 40px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0B1220;font-size:16px;line-height:1.55">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr><td class="topic" style="padding:0 0 10px;color:#077A54;font-size:12px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase">{topic}</td></tr>
<tr><td style="padding:0 0 18px;font-size:26px;line-height:1.2;font-weight:800;letter-spacing:-0.6px;color:#0B1220">{heading}</td></tr>
{code}<tr><td>{body}</td></tr>
{details}{if_not_you}</table></td></tr>
<tr><td class="mist" style="padding:22px 12px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.5;color:#5E6576;text-align:center">
<p style="margin:0 0 8px">{footer}</p>
<p style="margin:0">Sent by the Octa Pass server at {server}. Free, open source, end-to-end encrypted.</p>
</td></tr>
</table></td></tr></table>
</body></html>
"#,
            title = e(&self.subject),
            topic = e(self.topic),
            heading = e(&self.heading),
            footer = e(FOOTER),
            server = e(server),
        )
    }
}

/// Escapes text for HTML: names and device names are chosen by users, and land in other people's
/// mailboxes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum MailConfigError {
    #[error("OCTAPASS_SMTP_URL: {0}")]
    Url(#[from] lettre::transport::smtp::Error),
    #[error("OCTAPASS_SMTP_FROM: {0}")]
    From(#[from] lettre::address::AddressError),
}

impl Mailer {
    /// `None` when no SMTP URL is configured.
    pub fn from_config(config: &Config) -> Result<Option<Self>, MailConfigError> {
        let Some(url) = &config.smtp_url else {
            return Ok(None);
        };
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)?.build();
        let from = match &config.smtp_from {
            Some(from) => from.parse()?,
            None => format!("Octa Pass <noreply@{}>", host(&config.public_url)).parse()?,
        };
        Ok(Some(Self {
            transport,
            from,
            server: host(&config.public_url).to_owned(),
        }))
    }

    /// Sends in the background, so response times don't depend on the SMTP
    /// server and don't hint at which kind of email went out.
    pub fn send(&self, to: &str, email: Email) {
        let message = match to
            .parse::<Mailbox>()
            .map(|to| self.message(to, &email.content()))
        {
            Ok(Ok(message)) => message,
            // These errors can quote the address, so only the event is logged.
            Ok(Err(_)) => return tracing::warn!("couldn't build email"),
            Err(_) => return tracing::warn!("couldn't parse recipient"),
        };
        let transport = self.transport.clone();
        tokio::spawn(async move {
            if let Err(error) = transport.send(message).await {
                let status = error.status().map(|code| code.to_string());
                tracing::warn!(
                    kind = smtp_error_kind(&error),
                    status,
                    "sending email failed"
                );
            }
        });
    }
}

impl Mailer {
    /// Plain text for every client, and HTML with the logo for those that show it.
    fn message(&self, to: Mailbox, content: &Content) -> Result<Message, lettre::error::Error> {
        let logo = Attachment::new_inline(LOGO_CID.to_owned()).body(
            LOGO.to_vec(),
            ContentType::parse("image/png").expect("valid content type"),
        );
        Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(content.subject.clone())
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(content.text()))
                    .multipart(
                        MultiPart::related()
                            .singlepart(SinglePart::html(content.html(LOGO_CID, &self.server)))
                            .singlepart(logo),
                    ),
            )
    }
}

/// SMTP replies often echo the recipient, so logs get a category instead of the message.
fn smtp_error_kind(error: &lettre::transport::smtp::Error) -> &'static str {
    if error.is_permanent() {
        "permanent"
    } else if error.is_transient() {
        "transient"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_tls() {
        "tls"
    } else {
        "connection"
    }
}

/// `2026-11-02 14:05 UTC`, for emails.
pub fn readable_time(millis: i64) -> String {
    let rfc3339 = crate::db::rfc3339(millis);
    format!("{} {} UTC", &rfc3339[..10], &rfc3339[11..16])
}

fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', ':']).next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An SMTP server that refuses every recipient, quoting the address back
    /// the way real servers do.
    async fn refusing_smtp_server() -> std::net::SocketAddr {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            write.write_all(b"220 test ESMTP\r\n").await.unwrap();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = match line
                    .get(..4)
                    .unwrap_or_default()
                    .to_ascii_uppercase()
                    .as_str()
                {
                    "RCPT" => format!("550 5.1.1 {}: no such user\r\n", &line[8..]),
                    "QUIT" => "221 bye\r\n".to_owned(),
                    _ => "250 ok\r\n".to_owned(),
                };
                if write.write_all(reply.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    #[derive(Clone, Default)]
    struct Logs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn smtp_failures_are_logged_without_the_recipient() {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let smtp_url = format!("smtp://{}", refusing_smtp_server().await);
        let config = Config::from_lookup(|name| match name {
            "OCTAPASS_SMTP_URL" => Some(smtp_url.clone()),
            _ => None,
        })
        .unwrap();
        let mailer = Mailer::from_config(&config).unwrap().unwrap();
        mailer.send("victim@example.com", Email::AccountDeleted);

        let logged = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
                if text.contains("sending email failed") {
                    return text;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the failure is logged");
        assert!(logged.contains("kind=\"permanent\""), "{logged}");
        assert!(logged.contains("550"), "{logged}");
        assert!(!logged.contains("victim"), "{logged}");
    }

    #[test]
    fn formats_times_for_people() {
        assert_eq!(readable_time(1_761_177_600_123), "2025-10-23 00:00 UTC");
    }

    #[test]
    fn new_sign_in_names_the_device_and_where_to_sign_it_out() {
        let (subject, body) = Email::NewSignIn {
            device: "Pixel 9".into(),
            platform: "android".into(),
            at: readable_time(1_761_177_600_123),
        }
        .render();
        assert_eq!(subject, "New sign-in to your Octa Pass account");
        assert!(body.contains("Device: \"Pixel 9\" (android)"), "{body}");
        assert!(body.contains("Time: 2025-10-23 00:00 UTC"), "{body}");
        assert!(body.contains("Settings > Devices"), "{body}");
        assert!(body.contains("change your master password"), "{body}");
    }

    #[test]
    fn names_people_choose_are_escaped_in_html() {
        let html = Email::FamilyInvite {
            organiser: "<img src=x onerror=alert(1)> & \"Sam\"".into(),
        }
        .content()
        .html(LOGO_CID, "vault.example.com");
        assert!(!html.contains("<img src=x"), "{html}");
        assert!(
            html.contains("&lt;img src=x onerror=alert(1)&gt; &amp; &quot;Sam&quot;"),
            "{html}"
        );
    }

    #[test]
    fn html_has_no_remote_content_or_links() {
        for email in every_email() {
            let html = email.content().html(LOGO_CID, "vault.example.com");
            assert!(
                !html.contains("http://") && !html.contains("https://"),
                "{html}"
            );
            assert!(!html.contains("<a "), "{html}");
            assert!(html.contains(&format!("cid:{LOGO_CID}")), "{html}");
        }
    }

    #[test]
    fn codes_are_in_both_parts() {
        let content = Email::VerificationCode("482913".into()).content();
        assert!(content.text().contains("482913"));
        assert!(
            content
                .html(LOGO_CID, "vault.example.com")
                .contains("482913")
        );
        assert!(content.text().ends_with(FOOTER), "{}", content.text());
    }

    #[test]
    fn sends_text_and_html_with_the_logo_inline() {
        let config = Config::from_lookup(|name| match name {
            "OCTAPASS_SMTP_URL" => Some("smtp://127.0.0.1:2525".to_owned()),
            "OCTAPASS_PUBLIC_URL" => Some("https://vault.example.com".to_owned()),
            _ => None,
        })
        .unwrap();
        let mailer = Mailer::from_config(&config).unwrap().unwrap();
        let message = mailer
            .message(
                "sam@example.com".parse().unwrap(),
                &Email::TwoStepEnabled.content(),
            )
            .unwrap();
        let raw = String::from_utf8(message.formatted()).unwrap();
        assert!(raw.contains("multipart/alternative"), "{raw}");
        assert!(raw.contains("multipart/related"), "{raw}");
        assert!(raw.contains("text/plain"), "{raw}");
        assert!(raw.contains("text/html"), "{raw}");
        assert!(raw.contains("Content-ID: <logo@octapass>"), "{raw}");
        assert!(raw.contains("vault.example.com"), "{raw}");
    }

    fn every_email() -> Vec<Email> {
        vec![
            Email::VerificationCode("482913".into()),
            Email::AccountExists,
            Email::AccountDeleted,
            Email::FamilyInvite {
                organiser: "Maya Rahman".into(),
            },
            Email::OrgInvite {
                inviter: "Grace Hopper".into(),
            },
            Email::OrgProvisioned,
            Email::OrgRemoved,
            Email::EmergencyContactAdded {
                grantor: "Maya Rahman".into(),
            },
            Email::EmergencyAccessRequested {
                contact: "Omar".into(),
                releases_on: "2026-11-15 09:00 UTC".into(),
                reminder: false,
            },
            Email::EmergencyAccessDenied {
                grantor: "Maya Rahman".into(),
            },
            Email::EmergencyAccessReleased {
                other: "Omar".into(),
                to_grantor: true,
            },
            Email::EmergencyAccessReleased {
                other: "Maya Rahman".into(),
                to_grantor: false,
            },
            Email::TwoStepEnabled,
            Email::TwoStepDisabled,
            Email::RecoveryCodeUsed { left: 7 },
            Email::TwoStepLocked,
            Email::PasswordResetCode("739104".into()),
            Email::PasswordChanged,
            Email::SecretKeyRotated,
            Email::EmergencyTakeover {
                contact: "Omar".into(),
            },
            Email::PasswordReset,
            Email::NewSignIn {
                device: "Pixel 9".into(),
                platform: "android".into(),
                at: readable_time(1_761_177_600_123),
            },
        ]
    }

    /// Writes every email as HTML for a look in a browser:
    /// `OCTAPASS_EMAIL_PREVIEW=/some/dir cargo test -p octapass-server email_previews -- --ignored`
    #[test]
    #[ignore = "writes files; run by hand to look at the emails"]
    fn email_previews() {
        let dir = std::path::PathBuf::from(
            std::env::var("OCTAPASS_EMAIL_PREVIEW").expect("set OCTAPASS_EMAIL_PREVIEW"),
        );
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("logo.png"), LOGO).unwrap();
        for (i, email) in every_email().iter().enumerate() {
            let content = email.content();
            let html = content
                .html("logo", "vault.example.com")
                .replace("cid:logo", "logo.png");
            std::fs::write(dir.join(format!("{i:02}.html")), html).unwrap();
            std::fs::write(dir.join(format!("{i:02}.txt")), content.text()).unwrap();
        }
    }

    #[test]
    fn host_from_public_url() {
        assert_eq!(host("https://vault.example.com"), "vault.example.com");
        assert_eq!(host("http://127.0.0.1:8080/path"), "127.0.0.1");
    }
}
