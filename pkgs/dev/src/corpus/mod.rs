//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Agnostic corpus read/write logic.

use crate::prelude::*;

#[cfg(all(feature = "std", feature = "serde"))]
pub mod bls;
#[cfg(all(feature = "std", feature = "serde"))]
pub mod ecdsa;

/// A typed corpus entry pairing raw wire hex with expected details.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CorpusEntry<T> {
  pub raw: String,
  pub details: T,
}

/// Loads a JSON corpus file and parses it.
///
/// The file lives at `<manifest_dir>/corpus/<file>.json`.
///
/// # Panics
///
/// Panics if the file cannot be read or parsed.
#[cfg(feature = "std")]
pub fn load_corpus_json(manifest_dir: &str, file: &str) -> serde_json::Value {
  let path = format!("{manifest_dir}/corpus/{file}.json");
  let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
  serde_json::from_str(&data).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Extracts a named section from a JSON corpus as a typed vector.
///
/// # Panics
///
/// Panics if the section is missing or cannot be deserialized.
#[cfg(all(feature = "std", feature = "serde"))]
pub fn corpus_vectors<T: ::serde::de::DeserializeOwned>(corpus: &serde_json::Value, section: &str) -> Vec<T> {
  let val = corpus
    .get(section)
    .unwrap_or_else(|| panic!("missing section '{section}'"));
  serde_json::from_value(val.clone()).unwrap_or_else(|e| panic!("cannot parse '{section}': {e}"))
}

/// Reads a corpus JSON5 file from disk.
///
/// The file lives at `<manifest_dir>/corpus/<file>.json5`.
///
/// # Panics
///
/// Panics if the file cannot be read.
#[cfg(feature = "std")]
pub fn load_corpus_file(manifest_dir: &str, file: &str) -> String {
  let path = format!("{manifest_dir}/corpus/{file}.json5");
  std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Reads a corpus section from JSON5 text.
///
/// Parses `text` as `{ "section": { "label": { raw, details } } }`,
/// hex-decodes `raw` to bytes, calls `check(raw_bytes, &details,
/// label)` for each entry, and returns all details keyed by label.
///
/// # Panics
///
/// Panics if the section is missing, empty, or the check function
/// panics.
#[cfg(all(feature = "std", feature = "serde"))]
pub fn read_corpus<T: ::serde::de::DeserializeOwned>(
  text: &str,
  section: &str,
  mut check: impl FnMut(&[u8], &T, &str),
) -> BTreeMap<String, T> {
  use hex_conservative::FromHex;

  let mut outer: BTreeMap<String, serde_json::Value> =
    json5::from_str(text).unwrap_or_else(|e| panic!("{section}: parse: {e}"));
  let section_val = outer.remove(section).unwrap_or_else(|| panic!("{section}: not found"));
  let entries: BTreeMap<String, CorpusEntry<T>> =
    serde_json::from_value(section_val).unwrap_or_else(|e| panic!("{section}: {e}"));
  assert!(!entries.is_empty(), "{section}: empty");

  let mut result = BTreeMap::new();
  for (label, entry) in entries {
    let bytes = Vec::<u8>::from_hex(&entry.raw).unwrap_or_else(|e| panic!("{section}/{label}: hex: {e}"));
    check(&bytes, &entry.details, &label);
    result.insert(label, entry.details);
  }
  result
}

/// Serializes corpus entries to JSON in `{ raw, details }` format,
/// wrapped in a section key.
///
/// Produces `{ "section": { "label": { "raw": "", "details": T } } }`
/// so the output can be read back by [`read_corpus`] with a no-op
/// check function to verify the serde round-trip.
///
/// # Panics
///
/// Panics if serialization fails.
#[cfg(all(feature = "std", feature = "serde"))]
pub fn write_corpus<T: ::serde::Serialize>(section: &str, entries: &BTreeMap<String, T>) -> String {
  #[derive(::serde::Serialize)]
  struct Raw<'a, T: ::serde::Serialize> {
    raw: &'a str,
    details: &'a T,
  }
  let inner: BTreeMap<&str, Raw<T>> = entries
    .iter()
    .map(|(k, v)| (k.as_str(), Raw { raw: "", details: v }))
    .collect();
  let outer = BTreeMap::from([(section, inner)]);
  serde_json::to_string(&outer).unwrap_or_else(|e| panic!("write_corpus: {e}"))
}

/// Verifies the serde round-trip for a set of corpus entries.
///
/// Writes `items` to JSON via [`write_corpus`], reads them back
/// with [`read_corpus`] (no-op check), and asserts equality.
///
/// # Panics
///
/// Panics on round-trip mismatch.
#[cfg(all(feature = "std", feature = "serde"))]
pub fn assert_serde_rt<T>(section: &str, items: &BTreeMap<String, T>)
where
  T: ::serde::de::DeserializeOwned + ::serde::Serialize + PartialEq + core::fmt::Debug,
{
  let json = write_corpus(section, items);
  let rt = read_corpus::<T>(&json, section, |_, _, _| {});
  assert_eq!(*items, rt, "{section}: serde round-trip");
}
