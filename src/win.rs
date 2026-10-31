//! Тонкий слой поверх нужных нам Win32 API.
//!
//! В C#-версии каждый сканер (память по сигнатурам, RWX, VAD, скрытые модули,
//! .jar в службах) объявлял свои копии OpenProcess/VirtualQueryEx/CloseHandle и
//! заново писал один и тот же цикл обхода региона памяти. Здесь это сделано
//! один раз: `RegionWalker` — общий итератор по регионам адресного пространства
//! процесса, а `ProcessHandle` — RAII-обёртка, которая сама закрывает хендл
//! (вместо ручных `finally { CloseHandle(...) }` на каждый вызов).
//!
//! Модуль компилируется на любой платформе (сигнатуры extern "system" — это
//! просто объявления, линковка происходит только при финальной сборке под
//! Windows), но реально работает только там; не-Windows вызовы просто вернут
//! ошибку через `NotWindows`.

#![allow(dead_code)]

use std::ffi::c_void;
use std::io;

pub type Handle = isize;
pub const INVALID_HANDLE: Handle = 0;

// ---- Права доступа и константы состояния/типа памяти ----
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_QUERY_VM_READ: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x1000000;

pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;

pub const LIST_MODULES_ALL: u32 = 0x03;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemoryBasicInformation {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ServiceStatusProcess {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
    process_id: u32,
    service_flags: u32,
}

// MODULEENTRY32W (Toolhelp32)
#[repr(C)]
struct ModuleEntry32W {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: Handle,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

// PROCESSENTRY32W (Toolhelp32) — используется для поиска процессов по имени
// (javaw.exe, SearchIndexer.exe и т.п.), без внешних крейтов.
#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const TH32CS_SNAPMODULE: u32 = 0x00000008;
const TH32CS_SNAPMODULE32: u32 = 0x00000010;
const INVALID_HANDLE_VALUE: Handle = -1;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
    fn CloseHandle(h: Handle) -> i32;
    fn VirtualQueryEx(
        h_process: Handle,
        address: usize,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn ReadProcessMemory(
        h_process: Handle,
        base_address: usize,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn QueryFullProcessImageNameW(h_process: Handle, flags: u32, buffer: *mut u16, size: *mut u32) -> i32;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn GetLastError() -> u32;
}

#[link(name = "psapi")]
extern "system" {
    fn GetMappedFileNameW(h_process: Handle, addr: usize, buffer: *mut u16, size: u32) -> u32;
    fn EnumProcessModulesEx(
        h_process: Handle,
        modules: *mut Handle,
        cb: u32,
        needed: *mut u32,
        filter: u32,
    ) -> i32;
    fn GetModuleBaseNameA(h_process: Handle, h_module: Handle, name: *mut u8, size: u32) -> u32;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileTime {
    low: u32,
    high: u32,
}

impl FileTime {
    fn as_i64(self) -> i64 {
        ((self.high as i64) << 32) | (self.low as i64)
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetTickCount64() -> u64;
    fn GetSystemTimeAsFileTime(t: *mut FileTime);
    fn GetProcessTimes(h: Handle, creation: *mut FileTime, exit: *mut FileTime, kernel: *mut FileTime, user: *mut FileTime) -> i32;
}

/// Момент загрузки системы в 100-нс тиках FILETIME (1601-01-01 эпоха) —
/// нужен bypass-сканеру, чтобы понять, стартовала ли критическая служба
/// вовремя при загрузке или была перезапущена позже (подозрительно).
pub fn boot_time_filetime_100ns() -> i64 {
    let mut now = FileTime::default();
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let ticks_ms = unsafe { GetTickCount64() };
    now.as_i64() - (ticks_ms as i64) * 10_000
}

/// Время создания процесса в тех же 100-нс тиках FILETIME, либо None если
/// процесс не найден/недоступен.
pub fn process_creation_filetime_100ns(pid: u32) -> Option<i64> {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h == INVALID_HANDLE {
        return None;
    }
    let mut creation = FileTime::default();
    let mut exit = FileTime::default();
    let mut kernel = FileTime::default();
    let mut user = FileTime::default();
    let ok = unsafe { GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        None
    } else {
        Some(creation.as_i64())
    }
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
    fn OpenServiceW(scm: Handle, name: *const u16, access: u32) -> Handle;
    fn QueryServiceStatusEx(
        service: Handle,
        info_level: i32,
        buffer: *mut ServiceStatusProcess,
        cb_buf_size: u32,
        bytes_needed: *mut u32,
    ) -> i32;
    fn CloseServiceHandle(h: Handle) -> i32;
}

fn last_error() -> io::Error {
    #[cfg(windows)]
    unsafe {
        io::Error::from_raw_os_error(GetLastError() as i32)
    }
    #[cfg(not(windows))]
    {
        // На не-Windows хосте (например, при сборке/проверке этого кода в CI на Linux)
        // сами Win32-функции реально не вызываются — этот путь недостижим в рантайме,
        // но нужен, чтобы код собирался без `cfg(windows)`-обвязки на каждый вызов.
        let _ = unsafe { GetLastError() };
        io::Error::new(io::ErrorKind::Other, "not running on Windows")
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII-обёртка над HANDLE процесса: закрывается сама в Drop, как `using` в C#.
pub struct ProcessHandle(Handle);

impl ProcessHandle {
    pub fn open_query_vm_read(pid: u32) -> io::Result<Self> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_VM_READ, 0, pid) };
        if h == INVALID_HANDLE {
            return Err(last_error());
        }
        Ok(Self(h))
    }

    #[allow(dead_code)]
    pub fn raw(&self) -> Handle {
        self.0
    }

    /// Читает `buf.len()` байт по адресу `addr`. Возвращает реально прочитанное
    /// количество (может быть меньше при частичном чтении на границе региона).
    pub fn read_memory(&self, addr: usize, buf: &mut [u8]) -> usize {
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.0,
                addr,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut read,
            )
        };
        if ok == 0 {
            0
        } else {
            read
        }
    }

    /// Резолвит путь к файлу, на который отображена память по данному адресу
    /// (GetMappedFileNameW). None, если регион ни на что не мапится (в т.ч.
    /// классический признак секции под шелл-код — см. VAD-анализатор).
    pub fn mapped_file_name(&self, addr: usize) -> Option<String> {
        let mut buf = [0u16; 512];
        let len = unsafe { GetMappedFileNameW(self.0, addr, buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// Общий обход адресного пространства процесса через VirtualQueryEx.
    /// Раньше этот цикл был скопирован в пяти разных сканерах — теперь один.
    pub fn walk_regions(&self) -> RegionWalker<'_> {
        RegionWalker { handle: self, addr: 0, done: false }
    }

    /// Список загруженных модулей через Toolhelp32 (имя, путь, база, размер).
    pub fn enumerate_modules(&self, pid: u32) -> io::Result<Vec<ModuleInfo>> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let mut out = Vec::new();
        let mut entry: ModuleEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;
        let mut ok = unsafe { Module32FirstW(snap, &mut entry) };
        while ok != 0 {
            let path = wide_to_string(&entry.sz_exe_path);
            let name = wide_to_string(&entry.sz_module);
            if !path.is_empty() {
                out.push(ModuleInfo {
                    name,
                    file_name: path,
                    base_address: entry.mod_base_addr as usize,
                    size: entry.mod_base_size,
                });
            }
            entry.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;
            ok = unsafe { Module32NextW(snap, &mut entry) };
        }
        unsafe { CloseHandle(snap) };
        Ok(out)
    }

    /// Полный путь к exe процесса (аналог Process.MainModule.FileName).
    pub fn full_image_path(&self) -> Option<String> {
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(self.0, 0, buf.as_mut_ptr(), &mut size) };
        if ok == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        }
    }

    /// База jvm.dll в адресном пространстве процесса (нужна классовому дамперу).
    pub fn find_module_base(&self, name_ci: &str) -> Option<usize> {
        let mut modules = [0isize; 256];
        let mut needed = 0u32;
        let ok = unsafe {
            EnumProcessModulesEx(
                self.0,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<Handle>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return None;
        }
        let count = (needed as usize) / std::mem::size_of::<Handle>();
        for &h_module in &modules[..count.min(modules.len())] {
            let mut name_buf = [0u8; 260];
            let len =
                unsafe { GetModuleBaseNameA(self.0, h_module, name_buf.as_mut_ptr(), name_buf.len() as u32) };
            if len == 0 {
                continue;
            }
            let s = String::from_utf8_lossy(&name_buf[..len as usize]);
            if s.eq_ignore_ascii_case(name_ci) {
                return Some(h_module as usize);
            }
        }
        None
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub file_name: String,
    pub base_address: usize,
    pub size: u32,
}

/// Находит все процессы с данным именем (без учёта регистра, без ".exe") —
/// замена System.Diagnostics.Process.GetProcessesByName из C#-версии.
pub fn find_processes_by_name(name: &str) -> Vec<(u32, String)> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        let exe = wide_to_string(&entry.sz_exe_file);
        let proc_name = exe.strip_suffix(".exe").or_else(|| exe.strip_suffix(".EXE")).unwrap_or(&exe);
        if proc_name.eq_ignore_ascii_case(name) {
            out.push((entry.th32_process_id, proc_name.to_string()));
        }
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }
    unsafe { CloseHandle(snap) };
    out
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Итератор регионов адресного пространства процесса (аналог обхода VAD-дерева
/// через VirtualQueryEx, как это делают windbg `!address`/`!vad`).
pub struct RegionWalker<'a> {
    handle: &'a ProcessHandle,
    addr: usize,
    done: bool,
}

impl<'a> Iterator for RegionWalker<'a> {
    type Item = MemoryBasicInformation;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut mbi = MemoryBasicInformation::default();
        let written = unsafe {
            VirtualQueryEx(
                self.handle.0,
                self.addr,
                &mut mbi,
                std::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if written == 0 || mbi.region_size == 0 {
            self.done = true;
            return None;
        }
        let next = mbi.base_address.wrapping_add(mbi.region_size);
        if next <= self.addr {
            self.done = true;
        } else {
            self.addr = next;
        }
        Some(mbi)
    }
}

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
struct TokenPrivileges1 {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: u32, token_handle: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system_name: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable_all: i32,
        new_state: *const TokenPrivileges1,
        buffer_len: u32,
        previous_state: *mut TokenPrivileges1,
        return_len: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
}

/// Членство в группе Administrators само по себе НЕ даёт доступ на чтение
/// памяти процессов, принадлежащих SYSTEM/LocalService/NetworkService
/// (а именно там живут dnscache/pcasvc/lsass) — нужно явно включить
/// SeDebugPrivilege в токене через AdjustTokenPrivileges. Без этого
/// OpenProcess на такие процессы будет падать с Access Denied даже из-под
/// формально администраторской учётки. Привилегия физически ЕСТЬ в токене
/// только если exe запущен через "Запуск от имени администратора" (UAC-
/// повышение) — обычный запуск под учёткой-администратором без явного
/// повышения прав её не выдаст, и эта функция тогда вернёт false.
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: Handle = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let name = to_wide("SeDebugPrivilege");
        let mut luid = Luid::default();
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }
        let tp = TokenPrivileges1 { privilege_count: 1, privileges: [LuidAndAttributes { luid, attributes: SE_PRIVILEGE_ENABLED }] };
        let adjusted = AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0;
        // AdjustTokenPrivileges может вернуть "успех", но фактически не выдать
        // привилегию (если токен ей вообще не обладает) — это отражается только
        // в GetLastError() == ERROR_NOT_ALL_ASSIGNED, а не в возвращаемом значении.
        let last_error = GetLastError();
        CloseHandle(token);
        adjusted && last_error != ERROR_NOT_ALL_ASSIGNED
    }
}

/// Резолвит PID процесса, обслуживающего указанную службу, через Service Control
/// Manager (то же самое, что `sc queryex <имя>`). Если это не служба SCM, а
/// отдельный процесс (например SearchIndexer.exe) — вызывающий код сам делает
/// резервный поиск по имени процесса.
pub fn resolve_service_pid(service_name: &str) -> Option<u32> {
    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SC_STATUS_PROCESS_INFO: i32 = 0;

    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm == INVALID_HANDLE {
        return None;
    }
    let wide = to_wide(service_name);
    let svc = unsafe { OpenServiceW(scm, wide.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc == INVALID_HANDLE {
        unsafe { CloseServiceHandle(scm) };
        return None;
    }
    let mut status = ServiceStatusProcess::default();
    let mut needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut status,
            std::mem::size_of::<ServiceStatusProcess>() as u32,
            &mut needed,
        )
    };
    unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    if ok == 0 || status.process_id == 0 {
        None
    } else {
        Some(status.process_id)
    }
}
