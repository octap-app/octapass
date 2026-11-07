//! The one email a user gets when the relay pauses forwarding. It says what happened and what to
//! do, and names no sender. It goes out with a null return path so it can never bounce back here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pause {
    Alias,
    Account,
}

pub struct Notice {
    pub to: String,
    pub alias: String,
    pub pause: Pause,
    pub date: String,
    pub message_id: String,
}

impl Notice {
    /// The whole message, unsigned.
    pub fn render(&self, domain: &str) -> Vec<u8> {
        let (subject, opening) = match self.pause {
            Pause::Alias => (
                "Octa Pass stopped forwarding one masked email",
                format!(
                    "Octa Pass stopped forwarding mail sent to {}, because messages to your \
                     mailbox kept bouncing or were reported as spam.",
                    self.alias
                ),
            ),
            Pause::Account => (
                "Octa Pass stopped forwarding your masked emails",
                format!(
                    "Octa Pass stopped forwarding mail to all your masked emails, because \
                     messages to your mailbox kept bouncing or were reported as spam. The last \
                     one was sent to {}.",
                    self.alias
                ),
            ),
        };
        format!(
            "From: Octa Pass <postmaster@{domain}>\r\n\
             To: <{to}>\r\n\
             Subject: {subject}\r\n\
             Date: {date}\r\n\
             Message-ID: <{id}@{domain}>\r\n\
             Auto-Submitted: auto-generated\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             {opening}\r\n\
             \r\n\
             Mail sent to it is being refused until you turn it back on. To do that, open \
             Masked email in Octa Pass and turn the alias on. If your mailbox was full or \
             unavailable, fix that first.\r\n",
            to = self.to,
            date = self.date,
            id = self.message_id,
        )
        .into_bytes()
    }
}
