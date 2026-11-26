use std::collections::HashSet;
use std::io;
use std::time::{Duration, Instant};

use crate::win::{MemoryBasicInformation, ProcessHandle, MEM_COMMIT};

use super::signatures::{DetectionTag, Severity, SignatureDatabase};

pub struct ProcessDetection {
    pub process_id: u32,
    pub process_name: String,
    pub matches: HashSet<DetectionTag>,
    pub bytes_scanned: u64,
    pub bytes_skipped: u64,
    pub regions_scanned: usize,
    pub regions_incomplete: usize,
    pub elapsed: Duration,
}

impl ProcessDetection {
    pub fn is_complete(&self) -> bool {
        self.bytes_scanned > 0 && self.bytes_skipped == 0 && self.regions_incomplete == 0
    }

    pub fn has_confirmed(&self) -> bool {
        self.matches
            .iter()
            .any(|m| m.severity == Severity::Confirmed)
    }

    pub fn has_suspicious(&self) -> bool {
        self.matches
            .iter()
            .any(|m| m.severity == Severity::Suspicious)
    }
}

#[derive(Clone, Copy)]
pub struct ScanProgress {
    pub bytes_scanned: u64,
    pub total_estimate: u64,
}

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// 0x101 = PAGE_NOACCESS(0x01) | PAGE_GUARD(0x100); 0xEE = все "с чтением" биты
/// (READONLY/READWRITE/WRITECOPY/EXECUTE_READ/EXECUTE_READWRITE/EXECUTE_WRITECOPY).
fn is_readable(protect: u32) -> bool {
    (protect & 0x101) == 0 && (protect & 0xEE) != 0
}

/// Сигнатурный скан памяти процесса. Читает регион кусками по 4 МБ (чтобы не
/// аллоцировать гигабайты разом на огромных регионах), с перекрытием в
/// `max_pattern_len - 1` байт между кусками — иначе сигнатура, попавшая ровно
/// на границу чтения, была бы пропущена.
///
/// `family_filter`, если задан, ограничивает результат конкретными семействами.
pub fn scan_process(
    pid: u32,
    process_name: &str,
    db: &SignatureDatabase,
    family_filter: Option<&dyn Fn(&str) -> bool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> io::Result<ProcessDetection> {
    let start = Instant::now();
    let handle = ProcessHandle::open_query_vm_read(pid)?;

    let regions: Vec<MemoryBasicInformation> = handle
        .walk_regions()
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|m| m.state == MEM_COMMIT && is_readable(m.protect))
        .collect();

    let mut result = ProcessDetection {
        process_id: pid,
        process_name: process_name.to_string(),
        matches: HashSet::new(),
        bytes_scanned: 0,
        bytes_skipped: 0,
        regions_scanned: 0,
        regions_incomplete: 0,
        elapsed: Duration::ZERO,
    };

    scan_regions(
        &mut result,
        &regions,
        db,
        family_filter,
        |addr, buf| handle.read_memory(addr, buf),
        &mut on_progress,
    );
    result.elapsed = start.elapsed();
    Ok(result)
}

fn scan_regions(
    result: &mut ProcessDetection,
    regions: &[MemoryBasicInformation],
    db: &SignatureDatabase,
    family_filter: Option<&dyn Fn(&str) -> bool>,
    mut read_memory: impl FnMut(usize, &mut [u8]) -> usize,
    mut on_progress: impl FnMut(ScanProgress),
) {
    let total_estimate = regions.iter().map(|m| m.region_size as u64).sum();
    let overlap = db.max_pattern_len.saturating_sub(1);
    let mut buf = vec![0u8; overlap + CHUNK_SIZE];

    for region in regions {
        let mut addr = region.base_address;
        let region_end = region.base_address.saturating_add(region.region_size);
        let mut carry = 0usize;

        while addr < region_end {
            let want = (region_end - addr).min(CHUNK_SIZE);
            let read = read_memory(addr, &mut buf[carry..carry + want]);
            if read == 0 {
                break;
            }
            let scan_len = carry + read;

            db.scan_buffer(&buf[..scan_len], |tag| {
                if family_filter.is_none_or(|f| f(&tag.family)) {
                    result.matches.insert(tag.clone());
                }
            });

            result.bytes_scanned = result.bytes_scanned.saturating_add(read as u64);
            addr += read;

            let new_carry = overlap.min(scan_len);
            buf.copy_within(scan_len - new_carry..scan_len, 0);
            carry = new_carry;
        }

        if addr == region_end {
            result.regions_scanned += 1;
        } else {
            result.regions_incomplete += 1;
            result.bytes_skipped += (region_end - addr) as u64;
        }
        on_progress(ScanProgress {
            bytes_scanned: result.bytes_scanned,
            total_estimate,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_result() -> ProcessDetection {
        ProcessDetection {
            process_id: 1,
            process_name: "javaw".into(),
            matches: HashSet::new(),
            bytes_scanned: 0,
            bytes_skipped: 0,
            regions_scanned: 0,
            regions_incomplete: 0,
            elapsed: Duration::ZERO,
        }
    }

    fn database() -> SignatureDatabase {
        SignatureDatabase::load_from_str(
            r#"[{"Family":"Doomsday","Severity":"Confirmed","Patterns":["marker"]}]"#,
        )
        .unwrap()
    }

    fn region(size: usize) -> MemoryBasicInformation {
        MemoryBasicInformation {
            base_address: 4096,
            region_size: size,
            ..Default::default()
        }
    }

    #[test]
    fn zero_scanned_bytes_cannot_be_complete() {
        assert!(!empty_result().is_complete());
    }

    #[test]
    fn failed_region_is_counted_as_skipped() {
        let mut result = empty_result();
        scan_regions(
            &mut result,
            &[region(4096)],
            &database(),
            None,
            |_, _| 0,
            |_| {},
        );
        assert_eq!(result.bytes_skipped, 4096);
        assert_eq!(result.regions_incomplete, 1);
        assert_eq!(result.regions_scanned, 0);
        assert!(!result.is_complete());
    }

    #[test]
    fn partial_scan_keeps_detections_and_counts_unread_bytes() {
        let mut result = empty_result();
        scan_regions(
            &mut result,
            &[region(12)],
            &database(),
            None,
            |addr, buf| {
                if addr == 4096 {
                    buf[..6].copy_from_slice(b"marker");
                    6
                } else {
                    0
                }
            },
            |_| {},
        );
        assert!(result.has_confirmed());
        assert_eq!(result.bytes_scanned, 6);
        assert_eq!(result.bytes_skipped, 6);
        assert!(!result.is_complete());
    }

    #[test]
    fn finds_pattern_across_chunk_boundary() {
        let mut memory = vec![b'x'; CHUNK_SIZE + 16];
        memory[CHUNK_SIZE - 3..CHUNK_SIZE + 3].copy_from_slice(b"marker");
        let mut result = empty_result();
        scan_regions(
            &mut result,
            &[region(memory.len())],
            &database(),
            None,
            |addr, buf| {
                let start = addr - 4096;
                buf.copy_from_slice(&memory[start..start + buf.len()]);
                buf.len()
            },
            |_| {},
        );
        assert!(result.has_confirmed());
        assert!(result.is_complete());
        assert_eq!(result.bytes_scanned, memory.len() as u64);
        assert_eq!(result.regions_scanned, 1);
    }

    #[test]
    fn does_not_join_patterns_across_separate_regions() {
        let mut result = empty_result();
        let regions = [
            region(3),
            MemoryBasicInformation {
                base_address: 4099,
                ..region(3)
            },
        ];
        scan_regions(
            &mut result,
            &regions,
            &database(),
            None,
            |addr, buf| {
                buf.copy_from_slice(if addr == 4096 { b"mar" } else { b"ker" });
                buf.len()
            },
            |_| {},
        );
        assert!(result.matches.is_empty());
        assert!(result.is_complete());
    }
}
