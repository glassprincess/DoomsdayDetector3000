use crate::ui;
use crate::win;

/// Даёт выбрать javaw.exe, если их несколько. None, если процессов нет или
/// выбор некорректный (сообщение уже выведено в консоль).
pub fn pick() -> Option<(u32, String)> {
    let mut procs = ui::with_spinner("Ищем javaw.exe...", || win::find_processes_by_name("javaw"));
    procs.sort_by_key(|(pid, _)| *pid);

    if procs.is_empty() {
        ui::warn("javaw.exe processes not found.");
        return None;
    }

    println!();
    for (i, (pid, name)) in procs.iter().enumerate() {
        println!("  {}  PID {pid} — {name}", i + 1);
    }

    let answer = ui::prompt("Select process number (Enter = first):");
    let index: i64 = if answer.is_empty() {
        0
    } else {
        match answer.parse::<i64>() {
            Ok(n) => n - 1,
            Err(_) => -1,
        }
    };

    if index < 0 || index as usize >= procs.len() {
        ui::error("Invalid number.");
        return None;
    }

    Some(procs.remove(index as usize))
}
