mod core;
mod modules;
mod ui;
mod win;

use core::signatures::SignatureDatabase;

const EMBEDDED_SIGNATURES: &str = include_str!("../data/signatures.json");

fn main() {
    if !cfg!(windows) {
        eprintln!("DDD поддерживается только на Windows.");
        return;
    }

    ui::splash();

    if !win::enable_debug_privilege() {
        ui::warn("Не удалось включить SeDebugPrivilege — чтение памяти javaw.exe, скорее всего, будет падать с Access Denied.");
        ui::warn("Убедись, что exe запущен именно через «Запуск от имени администратора» (UAC), а не просто из-под учётки в группе Administrators без повышения.");
    }

    let db = match SignatureDatabase::load_from_str(EMBEDDED_SIGNATURES) {
        Ok(db) => Some(db),
        Err(e) => {
            ui::warn(&format!("Signature database not loaded: {e}"));
            None
        }
    };

    loop {
        let choice = ui::main_menu(db.is_some());
        ui::clear();
        match choice.as_str() {
            "1" => run_scan(db.as_ref()),
            "2" => print_credits(),
            "0" => {
                ui::begin_screen("Exiting", None);
                ui::success("Scan complete. See you.");
                return;
            }
            _ => {}
        }
        ui::pause();
    }
}

fn run_scan(db: Option<&SignatureDatabase>) {
    match db {
        Some(db) => modules::scan::run(db),
        None => {
            ui::begin_screen("Doomsday Scan", None);
            ui::warn("Signature database unavailable (not embedded in executable).");
        }
    }
}

fn print_credits() {
    ui::begin_screen("Credits", None);
    println!("  DDD — Doomsday Detector. Отдельная проверка под Doomsday.");
    println!("  Собран на коде и интерфейсе Jrss. Written and maintained by Lain.");
    println!();
    println!("  Signature scan of javaw.exe plus Doomsday class-name heuristics.");
    println!();
    ui::write_line("  Discord: rewakura", ui::Color::Red);
}
