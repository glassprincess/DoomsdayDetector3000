//! База сигнатур читерских клиентов: семейство → список строк/маркеров.
//!
//! В C#-версии автомат Ахо-Корасик был написан руками (goto-таблица на
//! `int[state*256+byte]`). Здесь вместо этого используется крейт `aho-corasick` —
//! тот же алгоритм, но проверенный, с SIMD-ускорением на x86_64. Это прямая
//! часть пункта "5) проверь логику, оптимизируй": меньше кода, меньше риска
//! ошибки в самодельной goto-таблице, быстрее сканирование.

use std::collections::HashSet;
use std::path::Path;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum Severity {
    Suspicious,
    Confirmed,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Confirmed => "CONFIRMED",
            Severity::Suspicious => "SUSPICIOUS",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DetectionTag {
    pub family: String,
    pub severity: Severity,
}

#[derive(Deserialize)]
struct SignatureFamilyJson {
    #[serde(rename = "Family")]
    family: String,
    #[serde(rename = "Severity")]
    severity: Severity,
    #[serde(rename = "Patterns")]
    patterns: Vec<String>,
}

pub struct SignatureDatabase {
    automaton: AhoCorasick,
    tags: Vec<DetectionTag>,
    pub family_count: usize,
    pub pattern_count: usize,
    pub max_pattern_len: usize,
}

impl SignatureDatabase {
    pub fn load_from_str(json: &str) -> Result<Self, String> {
        let families: Vec<SignatureFamilyJson> =
            serde_json::from_str(json).map_err(|e| format!("signatures.json parse error: {e}"))?;
        if families.is_empty() {
            return Err("signatures.json is empty — nothing to scan.".to_string());
        }

        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut tags: Vec<DetectionTag> = Vec::new();
        // (family, pattern, is_utf16) — как и в C#-версии, каждый паттерн кодируется
        // и как UTF-8, и как UTF-16LE (так Java-строки лежат в памяти JVM), с дедупом.
        let mut seen: HashSet<(String, String, bool)> = HashSet::new();
        let mut pattern_count = 0usize;
        let mut max_len = 0usize;

        for fam in &families {
            if fam.family.trim().is_empty() {
                return Err("Signature database contains a family without a name.".to_string());
            }
            for p in &fam.patterns {
                if p.is_empty() {
                    continue;
                }
                pattern_count += 1;
                let tag = DetectionTag { family: fam.family.clone(), severity: fam.severity };

                if seen.insert((fam.family.clone(), p.clone(), false)) {
                    let bytes = p.as_bytes().to_vec();
                    max_len = max_len.max(bytes.len());
                    patterns.push(bytes);
                    tags.push(tag.clone());
                }
                if seen.insert((fam.family.clone(), p.clone(), true)) {
                    let bytes: Vec<u8> = p.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                    max_len = max_len.max(bytes.len());
                    patterns.push(bytes);
                    tags.push(tag);
                }
            }
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|e| format!("failed to build Aho-Corasick automaton: {e}"))?;

        Ok(Self {
            automaton,
            tags,
            family_count: families.len(),
            pattern_count,
            max_pattern_len: max_len.max(1),
        })
    }

    /// Загрузка из файла на диске — не используется сейчас (сигнатуры
    /// встраиваются в бинарник через include_str!), но полезно оставить как
    /// публичный API для отладки без пересборки.
    #[allow(dead_code)]
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::load_from_str(&content)
    }

    /// Сканирует буфер целиком, вызывая `on_match` для каждой найденной сигнатуры.
    /// При потоковом сканировании памяти по кускам вызывающий код сам отвечает
    /// за то, чтобы соседние куски перекрывались на `max_pattern_len - 1` байт —
    /// иначе сигнатура, разрезанная границей чтения, будет пропущена.
    pub fn scan_buffer(&self, buf: &[u8], mut on_match: impl FnMut(&DetectionTag)) {
        for m in self.automaton.find_overlapping_iter(buf) {
            on_match(&self.tags[m.pattern().as_usize()]);
        }
    }
}
