//! Notebook index for the device app: which indexed identities exist as
//! notebooks, their local names, and archive flags. One JSON file
//! (`/.chain-notes/notebooks.json`); each notebook's notes/UTXO ledger
//! live in its own `state-<account>.json`. A notebook = an indexed
//! identity (`Identity::from_app_seed_indexed`, account 0 = the original
//! single-identity app, byte-identical). Local metadata only — names and
//! archive flags are NOT chain-recoverable after a wipe; notes recover
//! per address, and the index rebuilds by re-creating notebooks.
//! Design: ../../PLAN-chain-notes-notebooks.md.

use serde::{Deserialize, Serialize};

/// The name the migrated pre-notebooks notebook (account 0) gets — an
/// existing single-identity install becomes notebook "Main". Every other
/// notebook is created deliberately and starts unnamed.
pub const FIRST_NOTEBOOK_NAME: &str = "Main";

/// One notebook = one indexed identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookMeta {
    pub account: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookIndex {
    pub version: u32,
    pub notebooks: Vec<NotebookMeta>,
}

impl Default for NotebookIndex {
    fn default() -> Self {
        NotebookIndex { version: 1, notebooks: Vec::new() }
    }
}

impl NotebookIndex {
    pub fn get(&self, account: u32) -> Option<&NotebookMeta> {
        self.notebooks.iter().find(|n| n.account == account)
    }

    /// Add `account` unnamed if missing (naming is the caller's job — the
    /// create flow, or the migration rule). Returns true when added.
    pub fn ensure(&mut self, account: u32) -> bool {
        if self.get(account).is_some() {
            return false;
        }
        self.notebooks.push(NotebookMeta { account, name: String::new(), archived: false });
        self.notebooks.sort_by_key(|n| n.account);
        true
    }

    /// The account a "create notebook" gets: one past the highest known.
    pub fn next_account(&self) -> u32 {
        self.notebooks.iter().map(|n| n.account + 1).max().unwrap_or(0)
    }

    pub fn rename(&mut self, account: u32, name: &str) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.name = name.trim().to_string();
        }
    }

    pub fn set_archived(&mut self, account: u32, archived: bool) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.archived = archived;
        }
    }

    pub fn active(&self) -> impl Iterator<Item = &NotebookMeta> {
        self.notebooks.iter().filter(|n| !n.archived)
    }

    pub fn archived_count(&self) -> usize {
        self.notebooks.iter().filter(|n| n.archived).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_unnamed_and_sorts() {
        let mut ix = NotebookIndex::default();
        assert!(ix.ensure(3));
        assert!(ix.ensure(0));
        assert!(!ix.ensure(3));
        assert_eq!(ix.get(3).unwrap().name, "");
        assert_eq!(ix.notebooks[0].account, 0);
        assert_eq!(ix.next_account(), 4);
    }

    #[test]
    fn archive_and_rename() {
        let mut ix = NotebookIndex::default();
        ix.ensure(0);
        ix.ensure(1);
        ix.rename(1, "  Trips  ");
        assert_eq!(ix.get(1).unwrap().name, "Trips");
        ix.set_archived(0, true);
        assert_eq!(ix.active().count(), 1);
        assert_eq!(ix.archived_count(), 1);
    }
}
