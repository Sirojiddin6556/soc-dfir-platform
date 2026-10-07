#![forbid(unsafe_code)]

//! Local accounts from `/etc/passwd` and `/etc/group`.

use host_snapshot::UserAccount;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 {
                return None;
            }
            Some(PasswdEntry {
                name: fields[0].to_string(),
                uid: fields[2].parse().ok()?,
                gid: fields[3].parse().ok()?,
                gecos: fields[4].to_string(),
                home: fields[5].to_string(),
                shell: fields[6].to_string(),
            })
        })
        .collect()
}

pub fn parse_group(content: &str) -> Vec<GroupEntry> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 4 {
                return None;
            }
            Some(GroupEntry {
                name: fields[0].to_string(),
                gid: fields[2].parse().ok()?,
                members: fields[3]
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

/// Shells that do not allow an interactive login.
pub fn is_login_shell(shell: &str) -> bool {
    let shell = shell.trim();
    if shell.is_empty() {
        return false;
    }
    let base = shell.rsplit('/').next().unwrap_or(shell);
    !matches!(base, "nologin" | "false" | "sync" | "shutdown" | "halt")
}

const ADMIN_GROUPS: [&str; 3] = ["sudo", "wheel", "admin"];

pub fn build_accounts(passwd: &[PasswdEntry], groups: &[GroupEntry]) -> Vec<UserAccount> {
    let admin_groups: Vec<&GroupEntry> = groups
        .iter()
        .filter(|g| ADMIN_GROUPS.contains(&g.name.as_str()))
        .collect();
    passwd
        .iter()
        .map(|p| {
            let admin = p.uid == 0
                || admin_groups
                    .iter()
                    .any(|g| g.gid == p.gid || g.members.iter().any(|m| m == &p.name));
            let gecos_name = p.gecos.split(',').next().unwrap_or("").trim();
            UserAccount {
                name: p.name.clone(),
                uid: Some(p.uid),
                gid: Some(p.gid),
                sid: None,
                full_name: (!gecos_name.is_empty()).then(|| gecos_name.to_string()),
                home: (!p.home.is_empty()).then(|| p.home.clone()),
                shell: (!p.shell.is_empty()).then(|| p.shell.clone()),
                // Account lock state lives in /etc/shadow; it is not inferred.
                enabled: None,
                interactive: is_login_shell(&p.shell),
                admin,
                last_logon: None,
                source: "passwd".to_string(),
            }
        })
        .collect()
}

pub fn uid_name_map(passwd: &[PasswdEntry]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for entry in passwd {
        // First entry wins, like getpwuid().
        map.entry(entry.uid).or_insert_with(|| entry.name.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:105:111:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
alice:x:1000:1000:Alice Analyst,Room 4,,:/home/alice:/bin/zsh
bob:x:1001:1001::/home/bob:/bin/false
broken-line-without-fields
";

    const GROUP: &str = "root:x:0:
sudo:x:27:alice
docker:x:998:alice,bob
";

    #[test]
    fn parses_passwd_entries() {
        let entries = parse_passwd(PASSWD);
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0].name, "root");
        assert_eq!(entries[0].uid, 0);
        assert_eq!(entries[4].home, "/home/alice");
        assert_eq!(entries[4].shell, "/bin/zsh");
    }

    #[test]
    fn builds_accounts_with_admin_and_interactive_flags() {
        let accounts = build_accounts(&parse_passwd(PASSWD), &parse_group(GROUP));
        let get = |n: &str| accounts.iter().find(|a| a.name == n).unwrap();
        assert!(get("root").admin && get("root").interactive);
        assert!(!get("daemon").interactive && !get("daemon").admin);
        assert!(get("alice").admin, "alice is in sudo");
        assert_eq!(get("alice").full_name.as_deref(), Some("Alice Analyst"));
        assert!(get("postgres").interactive);
        assert!(!get("bob").interactive);
        assert!(!get("bob").admin, "docker membership is not sudo");
        assert_eq!(get("alice").enabled, None);
    }

    #[test]
    fn uid_map_resolves_names() {
        let map = uid_name_map(&parse_passwd(PASSWD));
        assert_eq!(map.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(map.get(&33).map(String::as_str), Some("www-data"));
    }
}
