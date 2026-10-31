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
    pub regions_scanned: usize,
    pub elapsed: Duration,
}

impl ProcessDetection {
    pub fn has_confirmed(&self) -> bool {
        self.matches.iter().any(|m| m.severity == Severity::Confirmed)
    }

    pub fn has_suspicious(&self) -> bool {
        self.matches.iter().any(|m| m.severity == Severity::Suspicious)
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
        .filter(|m| m.state == MEM_COMMIT && is_readable(m.protect))
        .collect();
    let total_estimate: u64 = regions.iter().map(|m| m.region_size as u64).sum();

    let mut result = ProcessDetection {
        process_id: pid,
        process_name: process_name.to_string(),
        matches: HashSet::new(),
        bytes_scanned: 0,
        regions_scanned: 0,
        elapsed: Duration::ZERO,
    };

    let overlap = db.max_pattern_len.saturating_sub(1);
    let mut buf = vec![0u8; overlap + CHUNK_SIZE];

    for (i, region) in regions.iter().enumerate() {
        let mut addr = region.base_address;
        let region_end = region.base_address.wrapping_add(region.region_size);
        let mut carry = 0usize;

        while addr < region_end {
            let want = (region_end - addr).min(CHUNK_SIZE);
            let read = handle.read_memory(addr, &mut buf[carry..carry + want]);
            if read == 0 {
                break;
            }
            let scan_len = carry + read;

            db.scan_buffer(&buf[..scan_len], |tag| {
                if family_filter.map_or(true, |f| f(&tag.family)) {
                    result.matches.insert(tag.clone());
                }
            });

            result.bytes_scanned = result.bytes_scanned.saturating_add(read as u64);
            addr += read;

            let new_carry = overlap.min(scan_len);
            buf.copy_within(scan_len - new_carry..scan_len, 0);
            carry = new_carry;
        }

        result.regions_scanned = i + 1;
        on_progress(ScanProgress {
            bytes_scanned: result.bytes_scanned,
            total_estimate,
        });
    }

    result.elapsed = start.elapsed();
    Ok(result)
}
