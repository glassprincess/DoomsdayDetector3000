//! Порт JvmContext.cs. НЕ использует Java Attach API — вместо этого читает
//! `gHotSpotVMStructs` прямо из памяти jvm.dll (тот же принцип, что и
//! Serviceability Agent/jhsdb): находим экспорт в PE-таблице jvm.dll, по нему
//! строим таблицу типов/смещений полей HotSpot, а по ней уже обходим
//! ClassLoaderDataGraph → ClassLoaderData → Klass и достаём имена классов.

use crate::win::ProcessHandle;

const VM_STRUCT_COUNT: usize = 788;

struct StructEntry {
    type_name: String,
    field_name: String,
    offset: u64,
    address: usize,
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
    narrow_oop_base: u64,
    narrow_oop_shift: i32,
    use_compressed_oops: bool,
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
            narrow_oop_base: 0,
            narrow_oop_shift: 0,
            use_compressed_oops: false,
            structs: Vec::new(),
        })
    }

    pub fn initialize(&mut self) -> bool {
        self.jvm_base = match self.handle.find_module_base("jvm.dll") {
            Some(b) => b,
            None => return false,
        };
        self.parse_vm_struct_table() && self.read_compressed_oops_info()
    }

    fn read_bytes(&self, addr: usize, buf: &mut [u8]) -> bool {
        addr != 0 && self.handle.read_memory(addr, buf) == buf.len()
    }

    fn read_u16(&self, addr: usize) -> u16 {
        let mut b = [0u8; 2];
        self.read_bytes(addr, &mut b);
        u16::from_le_bytes(b)
    }

    #[allow(dead_code)]
    fn read_u32(&self, addr: usize) -> u32 {
        let mut b = [0u8; 4];
        self.read_bytes(addr, &mut b);
        u32::from_le_bytes(b)
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
            self.structs.push(StructEntry { type_name, field_name, offset: raw.offset, address: raw.address });
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
        if !self.read_bytes(self.jvm_base + export_dir_entry.virtual_address as usize, &mut export_buf) {
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
        if !self.read_bytes(self.jvm_base + export_dir.address_of_names as usize, &mut names_buf)
            || !self.read_bytes(self.jvm_base + export_dir.address_of_name_ordinals as usize, &mut ordinals_buf)
            || !self.read_bytes(self.jvm_base + export_dir.address_of_functions as usize, &mut functions_buf)
        {
            return result;
        }

        for i in 0..export_dir.number_of_names as usize {
            let name_rva = u32::from_le_bytes(names_buf[i * 4..i * 4 + 4].try_into().unwrap());
            let ordinal = u16::from_le_bytes(ordinals_buf[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let func_off = ordinal * 4;
            if func_off + 4 > functions_buf.len() {
                continue;
            }
            let address = u32::from_le_bytes(functions_buf[func_off..func_off + 4].try_into().unwrap());
            let name = self.read_string(self.jvm_base + name_rva as usize, 200);
            if !name.is_empty() {
                result.push(ExportEntry { name, address });
            }
        }
        result
    }

    fn read_compressed_oops_info(&mut self) -> bool {
        let base = self.find_struct("CompressedOops", "_narrow_oop._base").map(|s| s.address);
        let shift = self.find_struct("CompressedOops", "_narrow_oop._shift").map(|s| s.address);
        let use_flag = self.find_struct("CompressedOops", "_narrow_oop._use_implicit_null_checks").map(|s| s.address);
        let (Some(base_addr), Some(shift_addr), Some(use_addr)) = (base, shift, use_flag) else {
            return false;
        };

        let mut base_buf = [0u8; 8];
        if !self.read_bytes(base_addr, &mut base_buf) {
            return false;
        }
        let mut shift_buf = [0u8; 4];
        if !self.read_bytes(shift_addr, &mut shift_buf) {
            return false;
        }
        let mut use_buf = [0u8; 1];
        self.read_bytes(use_addr, &mut use_buf);

        self.narrow_oop_base = u64::from_le_bytes(base_buf);
        self.narrow_oop_shift = i32::from_le_bytes(shift_buf);
        self.use_compressed_oops = use_buf[0] != 0;
        true
    }

    fn find_struct(&self, type_name: &str, field_name: &str) -> Option<&StructEntry> {
        self.structs.iter().find(|s| s.type_name == type_name && s.field_name == field_name)
    }

    fn get_struct_offset(&self, type_name: &str, field_name: &str) -> usize {
        self.find_struct(type_name, field_name).map(|s| s.offset as usize).unwrap_or(0)
    }

    pub fn read_pointer_raw(&self, addr: usize) -> usize {
        self.read_ptr(addr)
    }

    /// Обходит ClassLoaderDataGraph → ClassLoaderData → Klass и собирает имена
    /// всех загруженных классов — то, ради чего вообще нужен весь этот разбор
    /// PE/VMStructs выше.
    pub fn enumerate_all_class_names(&self) -> Vec<String> {
        let mut result = Vec::new();
        let Some(head) = self.find_struct("ClassLoaderDataGraph", "_head") else {
            return result;
        };
        let mut cld = self.read_pointer_raw(head.address);
        if cld == 0 {
            return result;
        }

        let klasses_offset = self.get_struct_offset("ClassLoaderData", "_klasses");
        let next_link_offset = self.get_struct_offset("Klass", "_next_link");
        let next_offset = self.get_struct_offset("ClassLoaderData", "_next");

        while cld != 0 {
            let mut klass = self.read_pointer_raw(cld + klasses_offset);
            while klass != 0 {
                let name = self.get_class_name(klass);
                if !name.is_empty() {
                    result.push(name);
                }
                klass = self.read_pointer_raw(klass + next_link_offset);
            }
            cld = self.read_pointer_raw(cld + next_offset);
        }
        result
    }

    fn get_class_name(&self, klass: usize) -> String {
        let name_offset = self.get_struct_offset("Klass", "_name");
        if name_offset == 0 {
            return String::new();
        }
        let symbol = self.read_pointer_raw(klass + name_offset);
        if symbol == 0 {
            return String::new();
        }
        let length = self.read_u16(symbol + 4);
        if length == 0 || length > 500 {
            return String::new();
        }
        let mut buf = vec![0u8; length as usize];
        if !self.read_bytes(symbol + 6, &mut buf) {
            return String::new();
        }
        // Doomsday встраивает в имена классов непечатные/не-ASCII байты, чтобы
        // ломать детекторы и читаемость дампа. Выбрасываем их здесь, чтобы имя
        // в дампе и в эвристиках было чистым ASCII (напр. `q0/hx2rmnoxos`).
        let raw = String::from_utf8_lossy(&buf);
        let clean: String = raw
            .chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != ' ')
            .collect();
        if clean.is_empty() {
            String::new()
        } else {
            clean
        }
    }
}
