pub mod doomsday_heuristic;
pub mod jvm_context;

use jvm_context::JvmContext;

use crate::ui;

pub fn check(pid: u32) {
    ui::section("Имена классов Doomsday");

    let classes = match collect(pid) {
        Ok(classes) => classes,
        Err(e) => {
            ui::error(&e);
            return;
        }
    };

    report_doomsday_findings(&classes);
}

fn collect(pid: u32) -> Result<Vec<String>, String> {
    let mut ctx = JvmContext::open(pid)
        .map_err(|e| format!("Could not open process. Run the scanner as administrator. ({e})"))?;

    let ready = ui::with_spinner(
        "Разбираем PE-таблицы jvm.dll и VMStructs...",
        || ctx.initialize(),
    );
    if !ready {
        return Err(
            "Failed to initialize JVM context. Make sure the process is a Java/javaw process."
                .to_string(),
        );
    }

    let classes = ui::with_spinner("Обходим ClassLoaderDataGraph...", || {
        ctx.enumerate_all_class_names()
    })?;
    if classes.is_empty() {
        return Err("No classes found. The JVM may not have loaded any classes yet.".to_string());
    }

    Ok(classes)
}

fn report_doomsday_findings(classes: &[String]) {
    let findings = doomsday_heuristic::scan(classes);

    if findings.is_clean() {
        ui::success("Паттернов имён Doomsday не найдено.");
        return;
    }

    if !findings.blatant.is_empty() {
        ui::warn(&format!(
            "BLATANT: {} классов с подозрительными lowercase+digit именами",
            findings.blatant.len()
        ));
        for name in findings.blatant.iter().take(SAMPLE_LIMIT) {
            println!("    ▸ {name}");
        }
    }

    if !findings.normal.is_empty() {
        ui::warn(&format!(
            "NORMAL: {} классов с коротким «пакетом» и хаотичным именем",
            findings.normal.len()
        ));
        for name in findings.normal.iter().take(SAMPLE_LIMIT) {
            println!("    ▸ {name}");
        }
    }

    if findings.vanilla_flagged() {
        ui::warn(&format!(
            "VANILLA: {} из первых {} классов имеют короткие обфусцированные имена",
            findings.vanilla_total_in_window, findings.vanilla_window
        ));
        for name in &findings.vanilla_sample {
            println!("    ▸ {name}");
        }
    }

    ui::warn("ЖЁЛТЫЙ: имена похожи на паттерны Doomsday. Эвристика не подтверждает наличие чита.");
}

const SAMPLE_LIMIT: usize = 10;
