use crate::core::process_scan;
use crate::core::signatures::SignatureDatabase;
use crate::modules::{class_dumper, java_processes};
use crate::ui;

pub fn run(db: &SignatureDatabase) {
    ui::begin_screen("Doomsday Scan", Some("javaw.exe: сигнатуры в памяти и имена классов."));
    ui::info(&format!("База сигнатур: {} семейств, {} сигнатур.", db.family_count, db.pattern_count));

    let Some((pid, name)) = java_processes::pick() else { return };

    match process_scan::scan_process(pid, &name, db, None, |p| {
        ui::progress_bar("Сканирование", p.bytes_scanned, p.total_estimate);
    }) {
        Ok(result) => ui::render_scan_result(&result),
        Err(e) => ui::error(&format!("Could not open process. Run the scanner as administrator. ({e})")),
    }

    class_dumper::check(pid);
}
