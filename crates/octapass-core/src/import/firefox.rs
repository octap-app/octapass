//! Firefox: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged`
//! (`toolkit/components/passwordmgr/LoginExport.sys.mjs`). Times are Unix milliseconds.
//!
//! `httpRealm` is set for logins saved from a site's HTTP authentication prompt, which have no
//! form; `formActionOrigin` is where a login form posts. `guid` is the login's id, kept so
//! importing the file again updates the logins.

use super::build::{Collector, ItemMeta, LoginFields, extra_fields, skipped_row, timestamp};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportResult};
use crate::matching::Site;

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let mut table = CsvTable::parse(text, b',')?;
    if !table.has(&["url"])
        || !table.has(&["username"])
        || !table.has(&["password"])
        || !table.has(&["httpRealm", "guid"])
    {
        return Err(invalid(
            "This is not a Firefox password export: it needs the columns url, username, password and httpRealm.",
        ));
    }
    let url = table.take(&["url"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let realm = table.take(&["httpRealm"]);
    let form_action = table.take(&["formActionOrigin"]);
    let guid = table.take(&["guid"]);
    let created = table.take(&["timeCreated"]);
    let last_used = table.take(&["timeLastUsed"]);
    let password_changed = table.take(&["timePasswordChanged"]);

    let mut out = Collector::default();
    let mut sync_logins = 0;
    for row in &table.rows {
        let url = row.get(url).unwrap_or_default().trim();
        // Firefox's own sync sign-in, not a website login.
        if url.starts_with("chrome://") {
            sync_logins += 1;
            out.skip(None);
            continue;
        }
        let mut urls = vec![url.to_string()];
        // Where the form posts, when that's another site (a separate sign-in host).
        if let (Some(action), Ok(page)) = (
            row.get(form_action).and_then(|a| Site::parse(a).ok()),
            Site::parse(url),
        ) && action.host != page.host
        {
            urls.push(action.url.origin().ascii_serialization());
        }
        let changed = timestamp(row.get(password_changed));
        let fields = LoginFields {
            urls,
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            custom_fields: extra_fields(table.extras(row)),
            http_realm: row.get(realm).map(str::to_string),
            meta: ItemMeta {
                created_at: timestamp(row.get(created)),
                // Firefox changes nothing else about a saved login.
                updated_at: changed.clone(),
                last_used_at: timestamp(row.get(last_used)),
                source_id: row.get(guid).map(str::to_string),
            },
            password_changed_at: changed,
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    if sync_logins > 0 {
        out.warn("Firefox's own sync sign-in was skipped.");
    }
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemDetails;

    #[test]
    fn parses_firefox_exports() {
        let result = parse(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
             \"https://www.example.com\",\"alice\",\"pw\",,\"https://login.example.com\",\"{1}\",\"1718000000000\",\"1718000300000\",\"1718000200000\"\n\
             \"https://router.local\",\"admin\",\"admin\",\"Router\",\"\",\"{2}\",\"1\",\"2\",\"3\"\n\
             \"chrome://FirefoxAccounts\",\"x\",\"{}\",\"Firefox Accounts credentials\",,\"{3}\",\"1\",\"2\",\"3\"\n",
        )
        .unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.warnings, ["Firefox's own sync sign-in was skipped."]);
        assert_eq!(
            result.items[0].overview.urls.as_deref().unwrap(),
            ["https://www.example.com", "https://login.example.com"]
        );
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        assert!(
            details.custom_fields.is_none(),
            "ids and timestamps are metadata"
        );
        let overview = &result.items[0].overview;
        assert_eq!(overview.created_at.as_deref(), Some("2024-06-10T06:13:20Z"));
        assert_eq!(overview.updated_at.as_deref(), Some("2024-06-10T06:16:40Z"));
        assert_eq!(
            overview.last_used_at.as_deref(),
            Some("2024-06-10T06:18:20Z")
        );
        assert_eq!(overview.imported_from.as_ref().unwrap().id, "{1}");
        assert_eq!(
            details.password_changed_at.as_deref(),
            Some("2024-06-10T06:16:40Z")
        );
        let ItemDetails::Login(router) = &result.items[1].details else {
            panic!()
        };
        assert_eq!(router.http_realm.as_deref(), Some("Router"));
        assert!(router.custom_fields.is_none());
        assert_eq!(
            result.items[1].overview.created_at, None,
            "1 ms is not a real date"
        );
    }
}
