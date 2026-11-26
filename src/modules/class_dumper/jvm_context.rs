//! Порт JvmContext.cs. НЕ использует Java Attach API — вместо этого читает
//! `gHotSpotVMStructs` прямо из памяти jvm.dll (тот же принцип, что и
//! Serviceability Agent/jhsdb): находим экспорт в PE-таблице jvm.dll, по нему
//! строим таблицу типов/смещений полей HotSpot, а по ней уже обходим
//! ClassLoaderDataGraph → ClassLoaderData → Klass и достаём имена классов.

use crate::win::ProcessHandle;
use std::collections::HashSet;

const VM_STRUCT_COUNT: usize = 788;

struct StructEntry {
    type_name: String,
    field_name: String,
    offset: u64,
    address: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestGraph {
        ctx: JvmContext,
        _symbol: Box<[u8; 32]>,
        klass: Box<[usize; 2]>,
        loader: Box<[usize; 2]>,
        _head: Box<usize>,
    }

    fn graph() -> TestGraph {
        let mut symbol = Box::new([0u8; 32]);
        let name = b"java/lang/String";
        symbol[4..6].copy_from_slice(&(name.len() as u16).to_le_bytes());
        symbol[6..6 + name.len()].copy_from_slice(name);
        let klass = Box::new([symbol.as_ptr() as usize, 0]);
        let loader = Box::new([klass.as_ptr() as usize, 0]);
        let head = Box::new(loader.as_ptr() as usize);
        let mut ctx = JvmContext::open(std::process::id()).unwrap();
        for (type_name, field_name, offset, address) in [
            (
                "ClassLoaderDataGraph",
                "_head",
                0,
                (&*head as *const usize) as usize,
            ),
            ("ClassLoaderData", "_klasses", 0, 0),
            ("ClassLoaderData", "_next", 8, 0),
            ("Klass", "_next_link", 8, 0),
            ("Klass", "_name", 0, 0),
            ("Symbol", "_length", 4, 0),
            ("Symbol", "_body", 6, 0),
        ] {
            ctx.structs.push(StructEntry {
                type_name: type_name.into(),
                field_name: field_name.into(),
                offset,
                address,
            });
        }
        TestGraph {
            ctx,
            _symbol: symbol,
            klass,
            loader,
            _head: head,
        }
    }

    #[test]
    fn enumerates_with_zero_offsets_without_compressed_oops_fields() {
        let graph = graph();
        assert_eq!(
            graph.ctx.enumerate_all_class_names().unwrap(),
            ["java/lang/String"]
        );
    }

    #[test]
    fn missing_required_field_is_an_error() {
        let mut graph = graph();
        graph
            .ctx
            .structs
            .retain(|entry| entry.field_name != "_next_link");
        assert!(graph.ctx.enumerate_all_class_names().is_err());
    }

    #[test]
    fn cyclic_class_list_is_an_error() {
        let mut graph = graph();
        graph.klass[1] = graph.klass.as_ptr() as usize;
        assert!(graph
            .ctx
            .enumerate_all_class_names()
            .unwrap_err()
            .contains("Cycle"));
    }

    #[test]
    fn cyclic_loader_list_is_an_error() {
        let mut graph = graph();
        graph.loader[1] = graph.loader.as_ptr() as usize;
        assert!(graph
            .ctx
            .enumerate_all_class_names()
            .unwrap_err()
            .contains("Cycle"));
    }

    #[test]
    fn unreadable_pointer_does_not_return_partial_success() {
        let mut graph = graph();
        graph.klass[1] = 1;
        assert!(graph.ctx.enumerate_all_class_names().is_err());
    }

    #[test]
    fn symbol_layout_comes_from_vm_structs() {
        let mut graph = graph();
        let name = b"java/lang/String";
        graph._symbol.fill(0);
        graph._symbol[..2].copy_from_slice(&(name.len() as u16).to_le_bytes());
        graph._symbol[8..8 + name.len()].copy_from_slice(name);
        for entry in &mut graph.ctx.structs {
            if entry.type_name == "Symbol" {
                entry.offset = if entry.field_name == "_length" { 0 } else { 8 };
            }
        }
        assert_eq!(
            graph.ctx.enumerate_all_class_names().unwrap(),
            ["java/lang/String"]
        );
    }

    #[test]
    fn missing_symbol_layout_is_an_error() {
        let mut graph = graph();
        graph
            .ctx
            .structs
            .retain(|entry| entry.type_name != "Symbol");
        assert!(graph.ctx.enumerate_all_class_names().is_err());
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawStructEntry {
    type_name: usize,
    field_name: usize,
    type_string: usize,
    is_static: i32,
    // компилятор сам вставит 4 байта паддинга здесь, чтобы offset лёг на границу 8 байт —
    // ровно то же самое, что даёт Pack=8 в оригинальной C#-структуре.
    offset: u64,
    address: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_reserved1: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

struct ExportEntry {
    name: String,
    address: u32,
}

pub struct JvmContext {
    handle: ProcessHandle,
    jvm_base: usize,
    structs: Vec<StructEntry>,
}

/// Читает структуру `T` из байтового буфера без проверки выравнивания —
/// ровно то же самое, что делает `Marshal.PtrToStructure` в оригинале.
unsafe fn read_struct<T: Copy>(buf: &[u8]) -> T {
    std::ptr::read_unaligned(buf.as_ptr() as *const T)
}

impl JvmContext {
    pub fn open(pid: u32) -> std::io::Result<Self> {
        let handle = ProcessHandle::open_query_vm_read(pid)?;
        Ok(Self {
            handle,
            jvm_base: 0,
            structs: Vec::new(),
        })
    }

    pub fn initialize(&mut self) -> bool {
        self.jvm_base = match self.handle.find_module_base("jvm.dll") {
            Some(b) => b,
            None => return false,
        };
        self.structs.clear();
        self.parse_vm_struct_table()
    }

    fn read_bytes(&self, addr: usize, buf: &mut [u8]) -> bool {
        addr != 0 && self.handle.read_memory(addr, buf) == buf.len()
    }

    fn read_u64(&self, addr: usize) -> u64 {
        let mut b = [0u8; 8];
        self.read_bytes(addr, &mut b);
        u64::from_le_bytes(b)
    }

    fn read_ptr(&self, addr: usize) -> usize {
        self.read_u64(addr) as usize
    }

    fn read_string(&self, addr: usize, max_length: usize) -> String {
        if addr == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; max_length];
        if !self.read_bytes(addr, &mut buf) {
            return String::new();
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    fn parse_vm_struct_table(&mut self) -> bool {
        let exports = self.parse_export_table();
        let Some(entry) = exports.iter().find(|e| e.name == "gHotSpotVMStructs") else {
            return false;
        };
        if entry.address == 0 {
            return false;
        }
        let table = self.read_ptr(self.jvm_base + entry.address as usize);
        let entry_size = std::mem::size_of::<RawStructEntry>();

        for i in 0..VM_STRUCT_COUNT {
            let mut buf = vec![0u8; entry_size];
            if !self.read_bytes(table + i * entry_size, &mut buf) {
                break;
            }
            let raw: RawStructEntry = unsafe { read_struct(&buf) };
            if raw.type_name == 0 {
                break;
            }
            let type_name = self.read_string(raw.type_name, 200);
            let field_name = self.read_string(raw.field_name, 200);
            if type_name.is_empty() || field_name.is_empty() {
                break;
            }
            self.structs.push(StructEntry {
                type_name,
                field_name,
                offset: raw.offset,
                address: raw.address,
            });
        }
        !self.structs.is_empty()
    }

    fn parse_export_table(&self) -> Vec<ExportEntry> {
        let mut result = Vec::new();

        let mut dos_buf = vec![0u8; std::mem::size_of::<ImageDosHeader>()];
        if !self.read_bytes(self.jvm_base, &mut dos_buf) {
            return result;
        }
        let dos: ImageDosHeader = unsafe { read_struct(&dos_buf) };
        if dos.e_magic != 0x5A4D {
            // "MZ"
            return result;
        }

        let mut nt_buf = vec![0u8; std::mem::size_of::<ImageNtHeaders64>()];
        if !self.read_bytes(self.jvm_base + dos.e_lfanew as usize, &mut nt_buf) {
            return result;
        }
        let nt: ImageNtHeaders64 = unsafe { read_struct(&nt_buf) };
        if nt.signature != 0x0000_4550 {
            // "PE\0\0"
            return result;
        }

        let export_dir_entry = &nt.optional_header.data_directory[0];
        if export_dir_entry.size == 0 {
            return result;
        }

        let mut export_buf = vec![0u8; std::mem::size_of::<ImageExportDirectory>()];
        if !self.read_bytes(
            self.jvm_base + export_dir_entry.virtual_address as usize,
            &mut export_buf,
        ) {
            return result;
        }
        let export_dir: ImageExportDirectory = unsafe { read_struct(&export_buf) };

        // sanity cap: a corrupted PE header would make us allocate gigabytes
        if export_dir.number_of_names > 200_000 || export_dir.number_of_functions > 200_000 {
            return result;
        }

        let mut names_buf = vec![0u8; export_dir.number_of_names as usize * 4];
        let mut ordinals_buf = vec![0u8; export_dir.number_of_names as usize * 2];
        let mut functions_buf = vec![0u8; export_dir.number_of_functions as usize * 4];
        if !self.read_bytes(
            self.jvm_base + export_dir.address_of_names as usize,
            &mut names_buf,
        ) || !self.read_bytes(
            self.jvm_base + export_dir.address_of_name_ordinals as usize,
            &mut ordinals_buf,
        ) || !self.read_bytes(
            self.jvm_base + export_dir.address_of_functions as usize,
            &mut functions_buf,
        ) {
            return result;
        }

        for i in 0..export_dir.number_of_names as usize {
            let name_rva = u32::from_le_bytes(names_buf[i * 4..i * 4 + 4].try_into().unwrap());
            let ordinal =
                u16::from_le_bytes(ordinals_buf[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let func_off = ordinal * 4;
            if func_off + 4 > functions_buf.len() {
                continue;
            }
            let address =
                u32::from_le_bytes(functions_buf[func_off..func_off + 4].try_into().unwrap());
            let name = self.read_string(self.jvm_base + name_rva as usize, 200);
            if !name.is_empty() {
                result.push(ExportEntry { name, address });
            }
        }
        result
    }

    fn find_struct(&self, type_name: &str, field_name: &str) -> Option<&StructEntry> {
        self.structs
            .iter()
            .find(|s| s.type_name == type_name && s.field_name == field_name)
    }

    fn required_struct(&self, type_name: &str, field_name: &str) -> Result<&StructEntry, String> {
        self.find_struct(type_name, field_name)
            .ok_or_else(|| format!("JVM field unavailable: {type_name}::{field_name}"))
    }

    fn read_pointer_at(&self, base: usize, offset: usize) -> Result<usize, String> {
        let addr = base.checked_add(offset).ok_or("JVM address overflow")?;
        let mut bytes = [0u8; 8];
        if !self.read_bytes(addr, &mut bytes) {
            return Err(format!(
                "Could not read JVM pointer at 0x{addr:X}; class scan incomplete."
            ));
        }
        Ok(u64::from_le_bytes(bytes) as usize)
    }

    /// Обходит ClassLoaderDataGraph → ClassLoaderData → Klass и собирает имена
    /// всех загруженных классов — то, ради чего вообще нужен весь этот разбор
    /// PE/VMStructs выше.
    pub fn enumerate_all_class_names(&self) -> Result<Vec<String>, String> {
        let mut result = Vec::new();
        let head = self.required_struct("ClassLoaderDataGraph", "_head")?;
        let mut cld = self.read_pointer_at(head.address, 0)?;

        let klasses_offset = self.required_struct("ClassLoaderData", "_klasses")?.offset as usize;
        let next_link_offset = self.required_struct("Klass", "_next_link")?.offset as usize;
        let next_offset = self.required_struct("ClassLoaderData", "_next")?.offset as usize;
        let name_offset = self.required_struct("Klass", "_name")?.offset as usize;
        let length_offset = self.required_struct("Symbol", "_length")?.offset as usize;
        let body_offset = self.required_struct("Symbol", "_body")?.offset as usize;
        let mut loaders = HashSet::new();
        let mut classes = HashSet::new();

        while cld != 0 {
            visit_node(&mut loaders, cld)?;
            let mut klass = self.read_pointer_at(cld, klasses_offset)?;
            while klass != 0 {
                visit_node(&mut classes, klass)?;
                let name = self.get_class_name(klass, name_offset, length_offset, body_offset)?;
                if !name.is_empty() {
                    result.push(name);
                }
                klass = self.read_pointer_at(klass, next_link_offset)?;
            }
            cld = self.read_pointer_at(cld, next_offset)?;
        }
        Ok(result)
    }

    fn get_class_name(
        &self,
        klass: usize,
        name_offset: usize,
        length_offset: usize,
        body_offset: usize,
    ) -> Result<String, String> {
        let symbol = self.read_pointer_at(klass, name_offset)?;
        if symbol == 0 {
            return Err("JVM class has no name; class scan incomplete.".into());
        }
        let length_addr = symbol
            .checked_add(length_offset)
            .ok_or("JVM symbol address overflow")?;
        let body_addr = symbol
            .checked_add(body_offset)
            .ok_or("JVM symbol address overflow")?;
        let mut length_bytes = [0u8; 2];
        if !self.read_bytes(length_addr, &mut length_bytes) {
            return Err("Could not read JVM class-name length; class scan incomplete.".into());
        }
        let length = u16::from_le_bytes(length_bytes);
        if length == 0 {
            return Err("JVM class has an empty name; class scan incomplete.".into());
        }
        let mut buf = vec![0u8; length as usize];
        if !self.read_bytes(body_addr, &mut buf) {
            return Err("Could not read JVM class name; class scan incomplete.".into());
        }
        // Doomsday встраивает в имена классов непечатные/не-ASCII байты, чтобы
        // ломать детекторы и читаемость дампа. Выбрасываем их здесь, чтобы имя
        // в дампе и в эвристиках было чистым ASCII (напр. `q0/hx2rmnoxos`).
        let raw = String::from_utf8_lossy(&buf);
        let clean: String = raw
            .chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != ' ')
            .collect();
        Ok(clean)
    }
}

fn visit_node(visited: &mut HashSet<usize>, address: usize) -> Result<(), String> {
    if !visited.insert(address) {
        return Err("Cycle in JVM class graph; class scan incomplete.".into());
    }
    if visited.len() > 1_000_000 {
        return Err("JVM class graph exceeds traversal limit; class scan incomplete.".into());
    }
    Ok(())
}
