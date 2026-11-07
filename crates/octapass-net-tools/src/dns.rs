//! Publishing DNS-01 answers. No provider is special: a hook script covers any DNS host, and the
//! Cloudflare and DigitalOcean APIs, which only need a bearer token, are built in.

use std::process::Command;

use serde_json::{Value, json};

use crate::fetch::agent;
use crate::{NetError, Result};

pub trait DnsProvider {
    /// Publishes a TXT record and returns what `remove` needs.
    fn publish(&self, name: &str, value: &str) -> Result<String>;
    fn remove(&self, name: &str, value: &str, handle: &str) -> Result<()>;
}

/// Runs a script with `OCTAPASS_ACME_ACTION` (`publish` or `remove`), `OCTAPASS_ACME_NAME` and
/// `OCTAPASS_ACME_VALUE` in its environment. The script is the user's own.
pub struct Hook {
    pub program: String,
}

impl Hook {
    fn run(&self, action: &str, name: &str, value: &str) -> Result<()> {
        let status = Command::new(&self.program)
            .env("OCTAPASS_ACME_ACTION", action)
            .env("OCTAPASS_ACME_NAME", name)
            .env("OCTAPASS_ACME_VALUE", value)
            .status()
            .map_err(|error| NetError::System(format!("Can't run {}: {error}", self.program)))?;
        if status.success() {
            Ok(())
        } else {
            Err(NetError::System(format!(
                "{} failed ({status}).",
                self.program
            )))
        }
    }
}

impl DnsProvider for Hook {
    fn publish(&self, name: &str, value: &str) -> Result<String> {
        self.run("publish", name, value).map(|()| String::new())
    }

    fn remove(&self, name: &str, value: &str, _handle: &str) -> Result<()> {
        self.run("remove", name, value)
    }
}

fn bearer_json(method: &str, url: &str, token: &str, body: Option<&Value>) -> Result<(u16, Value)> {
    let agent = agent();
    let authorization = format!("Bearer {token}");
    let response = match (method, body) {
        ("POST", Some(body)) => agent
            .post(url)
            .header("Authorization", &authorization)
            .send_json(body),
        ("DELETE", _) => agent
            .delete(url)
            .header("Authorization", &authorization)
            .call(),
        _ => agent
            .get(url)
            .header("Authorization", &authorization)
            .call(),
    };
    let mut response =
        response.map_err(|error| NetError::Network(format!("Can't reach the DNS API: {error}")))?;
    let status = response.status().as_u16();
    let value = response
        .body_mut()
        .read_json::<Value>()
        .unwrap_or(Value::Null);
    Ok((status, value))
}

/// The registered zone isn't known in advance: asks for each parent until one exists.
fn parents(name: &str) -> Vec<String> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    (1..labels.len().saturating_sub(0))
        .filter(|start| labels.len() - start >= 2)
        .map(|start| labels[start..].join("."))
        .collect()
}

pub struct Cloudflare {
    pub token: String,
    pub base: String,
}

impl Cloudflare {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base: "https://api.cloudflare.com/client/v4".to_owned(),
        }
    }

    fn zone(&self, name: &str) -> Result<String> {
        for candidate in parents(name) {
            let url = format!("{}/zones?name={candidate}", self.base);
            let (status, body) = bearer_json("GET", &url, &self.token, None)?;
            if status == 401 || status == 403 {
                return Err(NetError::Usage(
                    "Cloudflare refused the token. It needs Zone:DNS:Edit.".to_owned(),
                ));
            }
            if let Some(id) = body["result"][0]["id"].as_str() {
                return Ok(id.to_owned());
            }
        }
        Err(NetError::Usage(format!("No Cloudflare zone holds {name}.")))
    }
}

impl DnsProvider for Cloudflare {
    fn publish(&self, name: &str, value: &str) -> Result<String> {
        let zone = self.zone(name)?;
        let url = format!("{}/zones/{zone}/dns_records", self.base);
        let body = json!({ "type": "TXT", "name": name, "content": value, "ttl": 60 });
        let (status, answer) = bearer_json("POST", &url, &self.token, Some(&body))?;
        let id = answer["result"]["id"].as_str();
        match (status, id) {
            (200..=299, Some(id)) => Ok(format!("{zone}/{id}")),
            _ => Err(NetError::Network(format!(
                "Cloudflare refused the record ({status})."
            ))),
        }
    }

    fn remove(&self, _name: &str, _value: &str, handle: &str) -> Result<()> {
        let (zone, id) = handle.split_once('/').unwrap_or_default();
        let url = format!("{}/zones/{zone}/dns_records/{id}", self.base);
        bearer_json("DELETE", &url, &self.token, None).map(|_| ())
    }
}

pub struct DigitalOcean {
    pub token: String,
    pub base: String,
}

impl DigitalOcean {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base: "https://api.digitalocean.com/v2".to_owned(),
        }
    }
}

impl DnsProvider for DigitalOcean {
    fn publish(&self, name: &str, value: &str) -> Result<String> {
        for domain in parents(name) {
            let (status, _) = bearer_json(
                "GET",
                &format!("{}/domains/{domain}", self.base),
                &self.token,
                None,
            )?;
            if status == 401 || status == 403 {
                return Err(NetError::Usage(
                    "DigitalOcean refused the token.".to_owned(),
                ));
            }
            if status != 200 {
                continue;
            }
            let relative = name.strip_suffix(&format!(".{domain}")).unwrap_or(name);
            let body = json!({ "type": "TXT", "name": relative, "data": value, "ttl": 60 });
            let url = format!("{}/domains/{domain}/records", self.base);
            let (status, answer) = bearer_json("POST", &url, &self.token, Some(&body))?;
            return match (status, answer["domain_record"]["id"].as_u64()) {
                (200..=299, Some(id)) => Ok(format!("{domain}/{id}")),
                _ => Err(NetError::Network(format!(
                    "DigitalOcean refused the record ({status})."
                ))),
            };
        }
        Err(NetError::Usage(format!(
            "No DigitalOcean domain holds {name}."
        )))
    }

    fn remove(&self, _name: &str, _value: &str, handle: &str) -> Result<()> {
        let (domain, id) = handle.split_once('/').unwrap_or_default();
        let url = format!("{}/domains/{domain}/records/{id}", self.base);
        bearer_json("DELETE", &url, &self.token, None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parents_walk_up_to_the_registered_name() {
        assert_eq!(
            parents("_acme-challenge.a.b.example.com"),
            ["a.b.example.com", "b.example.com", "example.com"]
        );
        assert_eq!(parents("_acme-challenge.example.com"), ["example.com"]);
    }

    #[test]
    fn hook_scripts_get_the_record_in_their_environment() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("seen");
        let script = dir.path().join("hook.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$OCTAPASS_ACME_ACTION $OCTAPASS_ACME_NAME $OCTAPASS_ACME_VALUE\" >> {}\n",
                output.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let hook = Hook {
            program: script.display().to_string(),
        };
        let handle = hook.publish("_acme-challenge.a.test", "value").unwrap();
        hook.remove("_acme-challenge.a.test", "value", &handle)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            "publish _acme-challenge.a.test value\nremove _acme-challenge.a.test value\n"
        );
    }
}
