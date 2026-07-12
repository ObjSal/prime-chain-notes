//! Notebook index for the device app: which identities exist as
//! notebooks, their local names, and archive flags. One JSON file
//! (`/.chain-notes/notebooks.json`); each notebook's notes/UTXO ledger
//! lives in its own `state-<net>-<account>.json`, keyed by the unique
//! notebook KEY (`account` — the field name is historic).
//!
//! Two derivation schemes coexist (PLAN-chain-notes-seed-rotation.md):
//! - **legacy** (v1 entries, default on deserialize): an HKDF-indexed
//!   identity (`Identity::from_app_seed_indexed`, key doubles as the
//!   HKDF index; key 0 = the original single-identity app). FROZEN
//!   forever; network-independent keys.
//! - **bip86**: `Identity::from_bip86(app_seed, seed, net, bip_account,
//!   index)` — a receive index of a BIP-86 account under a rotation
//!   seed. Recoverable from the seed's 24 words alone in any wallet;
//!   per-network keys (coin_type 0'/1'). New notebooks are created in
//!   this scheme under the device's active (seed, account) context.
//!
//! Local metadata only — names and archive flags are NOT
//! chain-recoverable after a wipe; notes recover per address, and the
//! index rebuilds by re-creating notebooks.
//! Design: ../../PLAN-chain-notes-notebooks.md + PLAN-chain-notes-seed-rotation.md.

use serde::{Deserialize, Serialize};

/// The name the migrated pre-notebooks notebook (key 0) gets — an
/// existing single-identity install becomes notebook "Main". Every other
/// notebook is created deliberately and starts unnamed.
pub const FIRST_NOTEBOOK_NAME: &str = "Main";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// HKDF-indexed identity (the pre-recovery-seeds scheme). Default so
    /// v1 index files deserialize as-is.
    #[default]
    Legacy,
    /// BIP-86 receive index under a rotation seed.
    Bip86,
}

/// One notebook. `account` is the unique notebook KEY (state-file
/// routing + UI plumbing); for legacy entries it is ALSO the HKDF index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookMeta {
    pub account: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub scheme: Scheme,
    /// bip86 only: rotation seed index (keys::derive_seed_entropy).
    #[serde(default)]
    pub seed: u32,
    /// bip86 only: the hardened BIP-86 account.
    #[serde(default)]
    pub bip_account: u32,
    /// bip86 only: the receive-chain address index.
    #[serde(default)]
    pub index: u32,
}

impl NotebookMeta {
    /// Does this notebook belong to the device's active wallet context?
    /// Legacy notebooks are context-free (always visible — funds must
    /// never hide); bip86 notebooks scope to their (seed, account).
    pub fn in_context(&self, seed: u32, bip_account: u32) -> bool {
        match self.scheme {
            Scheme::Legacy => true,
            Scheme::Bip86 => self.seed == seed && self.bip_account == bip_account,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookIndex {
    pub version: u32,
    pub notebooks: Vec<NotebookMeta>,
}

impl Default for NotebookIndex {
    fn default() -> Self {
        NotebookIndex { version: 2, notebooks: Vec::new() }
    }
}

impl NotebookIndex {
    pub fn get(&self, account: u32) -> Option<&NotebookMeta> {
        self.notebooks.iter().find(|n| n.account == account)
    }

    /// Add legacy notebook `account` unnamed if missing (naming is the
    /// caller's job — the migration rule). Returns true when added.
    pub fn ensure(&mut self, account: u32) -> bool {
        if self.get(account).is_some() {
            return false;
        }
        self.notebooks.push(NotebookMeta {
            account,
            name: String::new(),
            archived: false,
            scheme: Scheme::Legacy,
            seed: 0,
            bip_account: 0,
            index: 0,
        });
        self.notebooks.sort_by_key(|n| n.account);
        true
    }

    /// Create a bip86 notebook at the next unused receive index of
    /// (`seed`, `bip_account`), named `name`. Returns its key.
    pub fn create_bip86(&mut self, seed: u32, bip_account: u32, name: &str) -> u32 {
        let account = self.next_account();
        let index = self.next_bip86_index(seed, bip_account);
        self.notebooks.push(NotebookMeta {
            account,
            name: name.trim().to_string(),
            archived: false,
            scheme: Scheme::Bip86,
            seed,
            bip_account,
            index,
        });
        self.notebooks.sort_by_key(|n| n.account);
        account
    }

    /// The key a new notebook gets: one past the highest known.
    pub fn next_account(&self) -> u32 {
        self.notebooks.iter().map(|n| n.account + 1).max().unwrap_or(0)
    }

    /// Next unused receive index within (`seed`, `bip_account`).
    pub fn next_bip86_index(&self, seed: u32, bip_account: u32) -> u32 {
        self.notebooks
            .iter()
            .filter(|n| {
                n.scheme == Scheme::Bip86 && n.seed == seed && n.bip_account == bip_account
            })
            .map(|n| n.index + 1)
            .max()
            .unwrap_or(0)
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

    /// Active notebooks visible in wallet context (`seed`, `bip_account`)
    /// — the set the list shows and wallet-level features operate on.
    pub fn visible(&self, seed: u32, bip_account: u32) -> impl Iterator<Item = &NotebookMeta> {
        self.active().filter(move |n| n.in_context(seed, bip_account))
    }

    /// Archived notebooks in wallet context.
    pub fn archived_in_context(
        &self,
        seed: u32,
        bip_account: u32,
    ) -> impl Iterator<Item = &NotebookMeta> {
        self.notebooks.iter().filter(move |n| n.archived && n.in_context(seed, bip_account))
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
        assert_eq!(ix.archived_in_context(0, 0).count(), 1);
    }

    #[test]
    fn v1_index_loads_as_legacy() {
        // A shipped v1 file has no scheme fields — every entry must
        // deserialize as a legacy notebook, byte-identical semantics.
        let v1 = r#"{"version":1,"notebooks":[{"account":0,"name":"Main","archived":false}]}"#;
        let ix: NotebookIndex = serde_json::from_str(v1).unwrap();
        let m = ix.get(0).unwrap();
        assert_eq!(m.scheme, Scheme::Legacy);
        assert!(m.in_context(7, 9)); // legacy is context-free
    }

    #[test]
    fn bip86_create_and_context() {
        let mut ix = NotebookIndex::default();
        ix.ensure(0); // a legacy survivor
        let k1 = ix.create_bip86(0, 0, "Notes");
        let k2 = ix.create_bip86(0, 0, "");
        let k3 = ix.create_bip86(1, 0, "PostRotation");
        assert_eq!((k1, k2, k3), (1, 2, 3));
        assert_eq!(ix.get(k1).unwrap().index, 0);
        assert_eq!(ix.get(k2).unwrap().index, 1); // same context → next index
        assert_eq!(ix.get(k3).unwrap().index, 0); // new seed → fresh indexes
        // Context filtering: seed 0/account 0 sees legacy + its two.
        let vis: Vec<u32> = ix.visible(0, 0).map(|m| m.account).collect();
        assert_eq!(vis, vec![0, 1, 2]);
        // After rotation to seed 1: legacy + the seed-1 notebook only.
        let vis: Vec<u32> = ix.visible(1, 0).map(|m| m.account).collect();
        assert_eq!(vis, vec![0, 3]);
    }

    #[test]
    fn v2_roundtrip_preserves_scheme() {
        let mut ix = NotebookIndex::default();
        ix.create_bip86(2, 1, "X");
        let json = serde_json::to_string(&ix).unwrap();
        let back: NotebookIndex = serde_json::from_str(&json).unwrap();
        let m = &back.notebooks[0];
        assert_eq!(m.scheme, Scheme::Bip86);
        assert_eq!((m.seed, m.bip_account, m.index), (2, 1, 0));
    }
}
