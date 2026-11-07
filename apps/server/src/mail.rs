//! Transactional email over SMTP.

use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

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

impl Email {
    /// Subject and plain-text body.
    pub fn render(&self) -> (String, String) {
        match self {
            Email::VerificationCode(code) => (
                format!("Your Octa Pass verification code: {code}"),
                format!(
                    "Your Octa Pass verification code is {code}.\n\n\
                     It expires in 15 minutes. If you didn't try to create an Octa Pass account, ignore this email."
                ),
            ),
            Email::AccountExists => (
                "Someone tried to create an Octa Pass account with your email".to_owned(),
                "Someone tried to create an Octa Pass account with this email address, but it already has one.\n\n\
                 If it was you, sign in instead. If it wasn't, you can ignore this email: nothing changed."
                    .to_owned(),
            ),
            Email::AccountDeleted => (
                "Your Octa Pass account was deleted".to_owned(),
                "Your Octa Pass account and everything in it were permanently deleted.\n\n\
                 Your devices were signed out, and this email address can be used for a new account. \
                 Encrypted server backups that still contain your data are rotated out within 30 days."
                    .to_owned(),
            ),
            Email::FamilyInvite { organiser } => (
                format!("{organiser} invited you to their Octa Pass family"),
                format!(
                    "{organiser} invited you to join their family on Octa Pass. Open the app to accept or decline.\n\n\
                     Family members share a Family vault and keep their own private vaults."
                ),
            ),
            Email::OrgInvite { inviter } => (
                format!("{inviter} invited you to an organisation on Octa Pass"),
                format!(
                    "{inviter} invited you to join their organisation on Octa Pass. Sign in with this email \
                     address to see the invitation, and the rules that come with it, before you accept. \
                     If you don't have an account yet, create one with this address.\n\n\
                     Your personal vault stays private: nobody in the organisation can read it. The invitation \
                     lasts 14 days. If you weren't expecting it, you can ignore this email."
                ),
            ),
            Email::OrgRemoved => (
                "You were removed from an organisation on Octa Pass".to_owned(),
                "An administrator removed you from your organisation on Octa Pass. Its vaults are no longer \
                 available to you. Your account and personal vault are unchanged."
                    .to_owned(),
            ),
            Email::EmergencyContactAdded { grantor } => (
                format!("{grantor} chose you as an emergency contact"),
                format!(
                    "{grantor} chose you as their emergency contact on Octa Pass.\n\n\
                     If something happens to them, you can request access from the app. They get a waiting \
                     period to deny the request; after it, you can open what they shared with you."
                ),
            ),
            Email::EmergencyAccessRequested {
                contact,
                releases_on,
                reminder,
            } => (
                if *reminder {
                    format!("Reminder: {contact} is waiting for emergency access")
                } else {
                    format!("{contact} requested emergency access to your Octa Pass account")
                },
                format!(
                    "{contact} requested emergency access to your Octa Pass account. Unless you deny it, \
                     access is released on {releases_on}.\n\n\
                     If you didn't expect this, deny the request in the app under Emergency access."
                ),
            ),
            Email::EmergencyAccessDenied { grantor } => (
                format!("{grantor} denied your emergency access request"),
                format!("{grantor} denied your emergency access request on Octa Pass. Nothing was released."),
            ),
            Email::EmergencyAccessReleased { other, to_grantor } => {
                if *to_grantor {
                    (
                        format!("Emergency access was released to {other}"),
                        format!(
                            "Emergency access to your Octa Pass account was released to {other}. \
                             If that's wrong, deny it in the app under Emergency access, then change your master \
                             password and rotate any vaults you shared."
                        ),
                    )
                } else {
                    (
                        format!("Emergency access to {other}'s Octa Pass account is ready"),
                        format!("Emergency access to {other}'s Octa Pass account was released. Open the app to view it."),
                    )
                }
            }
            Email::TwoStepEnabled => (
                "Two-step sign-in turned on".to_owned(),
                "Two-step sign-in is now on for your Octa Pass account. Signing in on a new device asks for a \
                 code from your authenticator app, a security key or a recovery code. Devices already signed in \
                 keep working.\n\n\
                 If you didn't do this, sign in and check Settings, then your security log."
                    .to_owned(),
            ),
            Email::TwoStepDisabled => (
                "Two-step sign-in turned off".to_owned(),
                "Two-step sign-in is now off for your Octa Pass account. New devices only need your master \
                 password and Secret Key.\n\n\
                 If you didn't do this, sign in, turn it back on in Settings and sign out devices you don't know."
                    .to_owned(),
            ),
            Email::RecoveryCodeUsed { left } => (
                "A recovery code was used to sign in to Octa Pass".to_owned(),
                format!(
                    "A new device signed in to your Octa Pass account with one of your two-step recovery codes. \
                     You have {left} left; you can make new ones in Settings.\n\n\
                     If it wasn't you, sign out that device in Settings and make new recovery codes."
                ),
            ),
            Email::TwoStepLocked => (
                "Several wrong two-step codes for your Octa Pass account".to_owned(),
                "Someone entered your master password and Secret Key, then several wrong two-step codes. \
                 Two-step sign-in is paused for a few minutes.\n\n\
                 If it wasn't you, your master password and Secret Key may be known to someone else."
                    .to_owned(),
            ),
            Email::PasswordResetCode(code) => (
                format!("Your Octa Pass reset code: {code}"),
                format!(
                    "Your code to reset your Octa Pass master password is {code}.\n\n\
                     It expires in 15 minutes. You'll also need your recovery code from your Recovery Kit. \
                     If you didn't ask to reset your master password, ignore this email: nothing changed."
                ),
            ),
            Email::PasswordChanged => (
                "Your Octa Pass master password was changed".to_owned(),
                "The master password of your Octa Pass account was changed. Your other devices were signed out: \
                 sign in on them with the new master password.\n\n\
                 If you didn't do this, someone knows your master password and Secret Key. Reset your master \
                 password with the recovery code from your Recovery Kit."
                    .to_owned(),
            ),
            Email::SecretKeyRotated => (
                "Your Octa Pass Secret Key was changed".to_owned(),
                "The Secret Key of your Octa Pass account was changed. Your other devices were signed out: sign \
                 in on them with the new Secret Key from your new Recovery Kit.\n\n\
                 If you didn't do this, someone knows your master password and Secret Key. Reset your master \
                 password with the recovery code from your Recovery Kit."
                    .to_owned(),
            ),
            Email::EmergencyTakeover { contact } => (
                format!("{contact} took over your Octa Pass account"),
                format!(
                    "{contact} used the emergency access you gave them to set a new master password and Secret \
                     Key for your Octa Pass account. Every device was signed out, the old recovery code stopped \
                     working, and two-step sign-in was turned off.\n\n\
                     To get back in, ask {contact} for the new Recovery Kit. If you didn't expect this, contact \
                     them right away and change the passwords stored in your vault."
                ),
            ),
            Email::PasswordReset => (
                "Your Octa Pass master password was reset".to_owned(),
                "The master password of your Octa Pass account was reset with your recovery code, and the \
                 recovery code was replaced. Every device was signed out: sign in with the new master password.\n\n\
                 If you didn't do this, someone had your recovery code and access to this email address. Reset \
                 your master password again if you still have the new Recovery Kit, then secure this email account."
                    .to_owned(),
            ),
            Email::NewSignIn {
                device,
                platform,
                at,
            } => (
                "New sign-in to your Octa Pass account".to_owned(),
                format!(
                    "A new device signed in to your Octa Pass account.\n\n\
                     Device: \"{device}\" ({platform})\n\
                     Time: {at}\n\n\
                     If it was you, there's nothing to do. If it wasn't, open Octa Pass on a device you trust, \
                     sign that device out under Settings > Devices, then change your master password. \
                     Whoever it was knew your master password and Secret Key."
                ),
            ),
        }
    }
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
        Ok(Some(Self { transport, from }))
    }

    /// Sends in the background, so response times don't depend on the SMTP
    /// server and don't hint at which kind of email went out.
    pub fn send(&self, to: &str, email: Email) {
        let (subject, body) = email.render();
        let message = match to.parse::<Mailbox>().map(|to| {
            Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(subject)
                .body(body)
        }) {
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
    fn host_from_public_url() {
        assert_eq!(host("https://vault.example.com"), "vault.example.com");
        assert_eq!(host("http://127.0.0.1:8080/path"), "127.0.0.1");
    }
}
