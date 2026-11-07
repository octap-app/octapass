//! The real polkit (D-Bus) and Secret Service calls.

use std::collections::HashMap;

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::Value;
use zeroize::Zeroizing;

use super::{Authorization, ItemKind, LinuxApi};
use crate::{Error, Result, platform_error};

/// `AllowUserInteraction`: polkit shows its password dialog.
const ALLOW_USER_INTERACTION: u32 = 1;
const APPLICATION: &str = "app.octap.desktop";

pub struct SystemApi;

/// polkit's `(ssssssuuua{ss})`: the action id first, then descriptions, defaults, annotations.
type ActionDescription = (
    String,
    String,
    String,
    String,
    String,
    String,
    u32,
    u32,
    u32,
    HashMap<String, String>,
);

fn dbus_error(error: impl std::fmt::Display) -> Error {
    Error::Platform(error.to_string())
}

fn authority(connection: &Connection) -> zbus::Result<Proxy<'_>> {
    Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
}

/// This process's start time in clock ticks (`/proc/self/stat` field 22), which polkit uses with
/// the pid so a recycled pid can't inherit an authorization.
fn process_start_time() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(dbus_error)?;
    // Fields after the parenthesised command name start at field 3.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| Error::Platform("unreadable /proc/self/stat".into()))
}

fn attributes(kind: ItemKind, tag: &str) -> HashMap<&'static str, String> {
    HashMap::from([
        ("application", APPLICATION.to_owned()),
        ("kind", kind.attribute().to_owned()),
        ("account", tag.to_owned()),
    ])
}

fn borrowed<'a>(attributes: &'a HashMap<&'static str, String>) -> HashMap<&'a str, &'a str> {
    attributes.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

impl LinuxApi for SystemApi {
    fn polkit_available(&self) -> bool {
        let Ok(connection) = Connection::system() else {
            return false;
        };
        let Ok(proxy) = authority(&connection) else {
            return false;
        };
        // EnumerateActions lists installed actions; ours is installed by the package.
        let actions: zbus::Result<Vec<ActionDescription>> = proxy.call("EnumerateActions", &("",));
        actions.is_ok_and(|actions| {
            actions
                .iter()
                .any(|action| action.0 == super::POLKIT_ACTION)
        })
    }

    fn authorize(&self, action: &str, message: &str) -> Result<Authorization> {
        let connection = Connection::system().map_err(dbus_error)?;
        let proxy = authority(&connection).map_err(dbus_error)?;
        let subject = (
            "unix-process",
            HashMap::from([
                ("pid", Value::U32(std::process::id())),
                ("start-time", Value::U64(process_start_time()?)),
            ]),
        );
        let details = HashMap::from([("polkit.message", message)]);
        let reply: zbus::Result<(bool, bool, HashMap<String, String>)> = proxy.call(
            "CheckAuthorization",
            &(subject, action, details, ALLOW_USER_INTERACTION, ""),
        );
        match reply {
            Ok((true, _, _)) => Ok(Authorization::Granted),
            Ok((false, _, _)) => Ok(Authorization::Refused),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str().ends_with(".NotSupported") =>
            {
                Ok(Authorization::Unavailable)
            }
            Err(error) => Err(platform_error("CheckAuthorization", error)),
        }
    }

    fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()> {
        let service = SecretService::connect(EncryptionType::Dh).map_err(dbus_error)?;
        let collection = service.get_default_collection().map_err(dbus_error)?;
        collection.ensure_unlocked().map_err(dbus_error)?;
        let attributes = attributes(kind, tag);
        collection
            .create_item(
                "Octa Pass device unlock",
                borrowed(&attributes),
                secret,
                true,
                "application/octet-stream",
            )
            .map(drop)
            .map_err(dbus_error)
    }

    fn load(&self, kind: ItemKind, tag: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let service = SecretService::connect(EncryptionType::Dh).map_err(dbus_error)?;
        let attributes = attributes(kind, tag);
        let found = service
            .search_items(borrowed(&attributes))
            .map_err(dbus_error)?;
        let Some(item) = found.unlocked.first().or(found.locked.first()) else {
            return Ok(None);
        };
        item.ensure_unlocked().map_err(dbus_error)?;
        item.get_secret()
            .map(|secret| Some(Zeroizing::new(secret)))
            .map_err(dbus_error)
    }

    fn delete(&self, kind: ItemKind, tag: &str) -> Result<()> {
        let service = SecretService::connect(EncryptionType::Dh).map_err(dbus_error)?;
        let attributes = attributes(kind, tag);
        let found = service
            .search_items(borrowed(&attributes))
            .map_err(dbus_error)?;
        for item in found.unlocked.iter().chain(&found.locked) {
            item.delete().map_err(dbus_error)?;
        }
        Ok(())
    }
}
