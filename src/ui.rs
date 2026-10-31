//! Аналог Jrss.Ui/ConsoleUi.cs. Цвет реализован через нативный Win32 console
//! API (GetStdHandle/SetConsoleTextAttribute) — то же самое, что делает
//! System.Console изнутри в .NET, так что поведение идентично оригиналу и
//! работает в классическом conhost без включения ANSI/VT-режима.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::core::process_scan::ProcessDetection;
use crate::core::signatures::Severity;

type Handle = isize;

const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (u32)-11

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

#[repr(C)]
struct ConsoleScreenBufferInfo {
    size: Coord,
    cursor_position: Coord,
    attributes: u16,
    window: SmallRect,
    maximum_window_size: Coord,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(std_handle: u32) -> Handle;
    fn GetConsoleScreenBufferInfo(h: Handle, info: *mut ConsoleScreenBufferInfo) -> i32;
    fn SetConsoleTextAttribute(h: Handle, attributes: u16) -> i32;
    fn FillConsoleOutputCharacterW(h: Handle, ch: u16, length: u32, coord: Coord, written: *mut u32) -> i32;
    fn FillConsoleOutputAttribute(h: Handle, attr: u16, length: u32, coord: Coord, written: *mut u32) -> i32;
    fn SetConsoleCursorPosition(h: Handle, coord: Coord) -> i32;
}

#[derive(Clone, Copy)]
pub enum Color {
    Red,
    DarkRed,
    Yellow,
    Green,
    Gray,
    DarkGray,
}

impl Color {
    // Значения совпадают с Win32-атрибутами консоли напрямую (как ConsoleColor в .NET).
    fn attr(self) -> u16 {
        match self {
            Color::Red => 12,
            Color::DarkRed => 4,
            Color::Yellow => 14,
            Color::Green => 10,
            Color::Gray => 7,
            Color::DarkGray => 8,
        }
    }
}

fn stdout_handle() -> Handle {
    unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
}

pub fn write_line(text: &str, color: Color) {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
    unsafe { SetConsoleTextAttribute(h, color.attr()) };
    println!("{text}");
    if had_info {
        unsafe { SetConsoleTextAttribute(h, info.attributes) };
    }
}

pub fn clear() {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(h, &mut info) } == 0 {
        return;
    }
    let cells = (info.size.x as u32) * (info.size.y as u32);
    let origin = Coord { x: 0, y: 0 };
    let mut written = 0u32;
    unsafe {
        FillConsoleOutputCharacterW(h, ' ' as u16, cells, origin, &mut written);
        FillConsoleOutputAttribute(h, info.attributes, cells, origin, &mut written);
        SetConsoleCursorPosition(h, origin);
    }
}

pub fn banner() {
    for line in BANNER_LINES {
        write_line(line, Color::Red);
    }
}

const BANNER_LINES: [&str; 6] = [
    "██████╗  ██████╗ ██████╗ ",
    "██╔══██╗██╔══██╗██╔══██╗",
    "██║  ██║██║  ██║██║  ██║",
    "██║  ██║██║  ██║██║  ██║",
    "██████╔╝██████╔╝██████╔╝",
    "╚═════╝ ╚═════╝ ╚═════╝ ",
];

fn cursor_row() -> Option<i16> {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(h, &mut info) } == 0 {
        None
    } else {
        Some(info.cursor_position.y)
    }
}

fn move_cursor_to(row: i16, col: i16) {
    unsafe { SetConsoleCursorPosition(stdout_handle(), Coord { x: col, y: row }) };
}

/// Одна строка баннера "проявляется" из тёмно-красного в яркий — печатаем
/// тускло, ждём кадр, перерисовываем ту же строку ярко поверх неё.
fn pulse_line(text: &str, delay_ms: u64) {
    let row_before = cursor_row();
    write_line(text, Color::DarkRed);
    thread::sleep(Duration::from_millis(delay_ms));
    if let Some(row) = row_before {
        move_cursor_to(row, 0);
        write_line(text, Color::Red);
    }
}

/// Печатает текст посимвольно — классический terminal typewriter-эффект.
fn typewriter(text: &str, color: Color, char_delay_ms: u64) {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
    unsafe { SetConsoleTextAttribute(h, color.attr()) };
    for ch in text.chars() {
        print!("{ch}");
        let _ = io::stdout().flush();
        thread::sleep(Duration::from_millis(char_delay_ms));
    }
    println!();
    if had_info {
        unsafe { SetConsoleTextAttribute(h, info.attributes) };
    }
}

/// Анимированная заставка — один раз при старте программы: лого "проявляется"
/// построчно, затем печатается тэглайн печатной машинкой. Дальше по программе
/// используется обычный мгновенный banner() — чтобы навигация по меню
/// оставалась быстрой, а не тормозила анимацией на каждом шаге.
pub fn splash() {
    clear();
    for line in BANNER_LINES {
        pulse_line(line, 22);
    }
    println!();
    typewriter("  doomsday detector — локальная проверка под Doomsday", Color::Gray, 6);
    thread::sleep(Duration::from_millis(220));
}

pub fn begin_screen(title: &str, description: Option<&str>) {
    clear();
    banner();
    section(title);
    if let Some(d) = description {
        if !d.trim().is_empty() {
            info(d);
            println!();
        }
    }
}

pub fn section(title: &str) {
    println!();
    write_line(&format!("── {title} ─────────────────────────────────────────"), Color::Red);
}

pub fn info(text: &str) {
    write_line(&format!("  • {text}"), Color::Gray);
}

pub fn warn(text: &str) {
    write_line(&format!("  ! {text}"), Color::Yellow);
}

pub fn error(text: &str) {
    write_line(&format!("  ✕ {text}"), Color::Red);
}

pub fn success(text: &str) {
    write_line(&format!("  ✓ {text}"), Color::Green);
}

pub fn dim(text: &str) {
    write_line(text, Color::DarkGray);
}

pub fn prompt(text: &str) -> String {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
    unsafe { SetConsoleTextAttribute(h, Color::Red.attr()) };
    print!("{text} ");
    let _ = io::stdout().flush();
    if had_info {
        unsafe { SetConsoleTextAttribute(h, info.attributes) };
    }
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim().to_string()
}

pub fn prompt_choice(text: &str, allowed: &[&str]) -> String {
    loop {
        let answer = prompt(text);
        if allowed.iter().any(|a| a.eq_ignore_ascii_case(&answer)) {
            return answer;
        }
        let mut sorted: Vec<&str> = allowed.to_vec();
        sorted.sort_unstable();
        error(&format!("Invalid choice. Allowed: {}.", sorted.join(", ")));
    }
}

pub fn pause() {
    println!();
    dim("  Press Enter to return to the main menu...");
    let mut discard = String::new();
    let _ = io::stdin().read_line(&mut discard);
}

fn menu_item(key: &str, label: &str, enabled: bool) {
    let h = stdout_handle();
    let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
    let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
    unsafe { SetConsoleTextAttribute(h, if enabled { Color::Red.attr() } else { Color::DarkGray.attr() }) };
    print!("  {:>2}  ", key);
    unsafe { SetConsoleTextAttribute(h, if enabled { Color::Gray.attr() } else { Color::DarkGray.attr() }) };
    if enabled {
        println!("{label}");
    } else {
        println!("{label} (unavailable)");
    }
    if had_info {
        unsafe { SetConsoleTextAttribute(h, info.attributes) };
    }
}

pub fn main_menu(memory_scan_available: bool) -> String {
    begin_screen("Main Menu", None);
    let items: [(&str, &str, bool); 3] = [
        ("1", "Doomsday Scan (signatures + class names)", memory_scan_available),
        ("2", "Credits", true),
        ("0", "Exit", true),
    ];
    // Пункты меню "проявляются" один за другим — лёгкий, недорогой штрих,
    // не тормозящий навигацию (суммарно ~110мс на всё меню).
    for (key, label, enabled) in items {
        menu_item(key, label, enabled);
        thread::sleep(Duration::from_millis(12));
    }
    println!();
    prompt_choice("Choose action:", &["0", "1", "2"])
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub fn progress_bar(label: &str, bytes_scanned: u64, total_estimate: u64) {
    let total = total_estimate.max(1);
    let percent = ((bytes_scanned as f64) * 100.0 / (total as f64)).clamp(0.0, 100.0) as i32;
    let filled = (percent / 4) as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(25 - filled);
    print!("\r  {label} [{bar}] {percent:3}%  {}   ", human_bytes(bytes_scanned));
    let _ = io::stdout().flush();
}

pub fn render_scan_result(result: &ProcessDetection) {
    println!();
    println!(
        "  Done in {:.1}s. Regions: {}. Scanned: {}.",
        result.elapsed.as_secs_f64(),
        result.regions_scanned,
        human_bytes(result.bytes_scanned)
    );
    if result.matches.is_empty() {
        success("●  CLEAN — no known signatures found");
        return;
    }
    if result.has_confirmed() {
        alert_flash("  ✕ ●  RED LIGHT — cheat client detected", Color::Red);
    } else if result.has_suspicious() {
        warn("●  YELLOW LIGHT — suspicious indicators found");
    }
    let mut sorted: Vec<_> = result.matches.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.family.cmp(&b.family)));
    for tag in sorted {
        let color = if tag.severity == Severity::Confirmed { Color::Red } else { Color::Yellow };
        write_line(
            &format!(
                "  ▸ {}.EXE (PID {}) — {} [{}]",
                result.process_name.to_uppercase(),
                result.process_id,
                tag.family,
                tag.severity.label()
            ),
            color,
        );
    }
}

/// Крутит спиннер в отдельном потоке, пока выполняется `work` — для "тихих"
/// операций, которые раньше просто вешали экран без обратной связи (резолв
/// PID службы, обход VAD-дерева, разбор PE-таблиц JVM). НЕ использовать вокруг
/// кода, который сам параллельно пишет в консоль (например, скан с
/// progress_bar) — потоки будут писать в консоль одновременно и испортят вывод.
pub fn with_spinner<T>(label: &str, work: impl FnOnce() -> T) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);
    let label_owned = label.to_string();

    let spinner = thread::spawn(move || {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let h = stdout_handle();
        let mut i = 0usize;
        while !stop_worker.load(Ordering::Relaxed) {
            let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
            let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
            unsafe { SetConsoleTextAttribute(h, Color::DarkGray.attr()) };
            print!("\r  {} {label_owned}   ", FRAMES[i % FRAMES.len()]);
            let _ = io::stdout().flush();
            if had_info {
                unsafe { SetConsoleTextAttribute(h, info.attributes) };
            }
            i += 1;
            thread::sleep(Duration::from_millis(80));
        }
        print!("\r{}\r", " ".repeat(label_owned.chars().count() + 6));
        let _ = io::stdout().flush();
    });

    let result = work();
    stop.store(true, Ordering::Relaxed);
    let _ = spinner.join();
    result
}

/// Мигает строкой на месте (красный/жёлтый) несколько раз перед тем, как
/// оставить её финальным цветом — для драматического акцента на "читер
/// обнаружен", а не сухого статичного вывода.
pub fn alert_flash(text: &str, final_color: Color) {
    let padded_len = text.chars().count() + 4;
    for i in 0..5 {
        let flash_color = if i % 2 == 0 { Color::Red } else { Color::Yellow };
        let h = stdout_handle();
        let mut info: ConsoleScreenBufferInfo = unsafe { std::mem::zeroed() };
        let had_info = unsafe { GetConsoleScreenBufferInfo(h, &mut info) } != 0;
        unsafe { SetConsoleTextAttribute(h, flash_color.attr()) };
        print!("\r{text:<padded_len$}");
        let _ = io::stdout().flush();
        if had_info {
            unsafe { SetConsoleTextAttribute(h, info.attributes) };
        }
        thread::sleep(Duration::from_millis(110));
    }
    print!("\r");
    write_line(text, final_color);
}
