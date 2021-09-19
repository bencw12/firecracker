extern crate rand;
use rand::seq::SliceRandom;

use std::io::{Read, Seek, SeekFrom};
use std::convert::TryInto;

use vm_memory::{Address, Bytes, ByteValued, GuestAddress, GuestMemoryMmap};

use super::elf;
use super::extable;
use super::Error;
use arch::x86_64::layout::__START_KERNEL_MAP;   
pub type Result<T> = std::result::Result<T, Error>;

pub const _STEXT: &str = "_stext";
pub const _ETEXT: &str = "_etext";
pub const _SINITTEXT: &str = "_sinittext";
pub const _EINITTEXT: &str = "_einittext";
pub const __START_ORC_UNWIND_IP: &str = "__start_orc_unwind_ip";
pub const __STOP_ORC_UNWIND_IP: &str = "__stop_orc_unwind_ip";
pub const __START_ORC_UNWIND: &str = "__start_orc_unwind";
pub const __START___EX_TABLE: &str = "__start___ex_table";
pub const __STOP___EX_TABLE: &str = "__stop___ex_table";

static mut ADDR_STEXT: u64 = 0;
static mut ADDR_ETEXT: u64 = 0;
static mut ADDR_SINITTEXT: u64 = 0;
static mut ADDR_EINITTEXT: u64 = 0;
static mut ADDR__START_ORC_UNWIND_IP: u64 = 0;
static mut ADDR__STOP_ORC_UNWIND_IP: u64 = 0;
static mut ADDR__START_ORC_UNWIND: u64 = 0;
#[allow(non_snake_case)]
static mut ADDR__START___EX_TABLE: u64 = 0;
#[allow(non_snake_case)]
static mut ADDR__STOP___EX_TABLE: u64 = 0;
static mut ADDR_PERCPU_START: u64 = 0;
static mut ADDR_PERCPU_END: u64 = 0;


unsafe impl ByteValued for elf::Elf64_Shdr {}
unsafe impl ByteValued for elf::Elf64_Sym {}
unsafe impl ByteValued for extable::ExTableEntry {}

//Translation of kernel macro
fn align(addr: u64, align: u64) -> Result<u64> {
    let mask = align - 1;
    Ok((addr + mask) & !mask)
}

fn swap_ex_entries(
    ex_table: &mut Vec<extable::ExTableEntry>,
    start_ex_table: u64,
    x: usize,
    y: usize,
    size: usize,
) {
    let addr = start_ex_table - __START_KERNEL_MAP;
    let addr_x = addr + (x * size) as u64;
    let addr_y = addr + (y * size) as u64;
    let delta = addr_y - addr_x;

    let tmp_insn = ex_table[x].insn;
    let tmp_fixup = ex_table[x].fixup;
    let tmp_handler = ex_table[x].handler;

    ex_table[x].insn = ex_table[y].insn + delta as i32;
    ex_table[y].insn = tmp_insn - delta as i32;

    ex_table[x].fixup = ex_table[y].fixup + delta as i32;
    ex_table[y].fixup = tmp_fixup - delta as i32;

    ex_table[x].handler = ex_table[y].handler + delta as i32;
    ex_table[y].handler = tmp_handler - delta as i32;
}

fn cmp_ex_sort(
    extable: &mut Vec<extable::ExTableEntry>,
    start_ex_table: u64,
    i: usize,
    j: usize,
    size: usize,
) -> i32 {
    assert!(i < j);
    //Calculate the address of each entry by adding offset to the beginning of the ex table
    let addr = start_ex_table - __START_KERNEL_MAP;
    let addr_i = addr + (i * size) as u64;
    let addr_j = addr + (j * size) as u64;

    //These are unsigned long in C
    let insn_i = addr_i as i32 + extable[i].insn;
    let insn_j = addr_j as i32 + extable[j].insn;

    //Compare actual instruction addresses
    if insn_i > insn_j {
        return 1;
    }
    if insn_i < insn_j {
        return -1;
    }

    return 0;
}

//linux kernel bottom up heapsort lib/sort.c
fn sort_ex_table(
    ex_table: &mut Vec<extable::ExTableEntry>,
    num_entries: usize,
    start_ex_table: u64,
) {
    let size = std::mem::size_of::<extable::ExTableEntry>();
    let mut mid = num_entries / 2;
    let mut n = num_entries;

    loop {
        if mid != 0 {
            mid -= 1;
        } else {
            n -= 1;
            if n != 0 {
                swap_ex_entries(ex_table, start_ex_table, 0, n, size);
            } else {
                break;
            }
        }

        let mut b = mid;
        let mut c = 2 * b + 1;
        let d = c + 1;

        while d < n {
            c = 2 * b + 1;
            let d = c + 1;

            if !(d < n) {
                break;
            }

            b = if cmp_ex_sort(ex_table, start_ex_table, c, d, size) >= 0 {
                c
            } else {
                d
            };
        }

        if d == n {
            b = c;
        }

        while b != mid && cmp_ex_sort(ex_table, start_ex_table, mid, b, size) >= 0 {
            b = (b - 1) / 2;
        }
        c = b;
        while b != mid {
            b = (b - 1) / 2;
            swap_ex_entries(ex_table, start_ex_table, b, c, size);
        }
    }
}

fn update_ex_table(
    guest_mem: &GuestMemoryMmap,
    sections: &Vec<elf::Elf64_Shdr>,
    sections_size: usize,
    offsets: &Vec<i64>,
    phys_offset: u64,
) -> Result<()> {
    unsafe {
        #[allow(non_snake_case)]
        let addr___start___ex_table = ADDR__START___EX_TABLE;
        #[allow(non_snake_case)]
        let addr___stop___ex_table = ADDR__STOP___EX_TABLE;

        let num_entries = (addr___stop___ex_table - addr___start___ex_table)
            / std::mem::size_of::<extable::ExTableEntry>() as u64;


        //Read the exception table to a buffer
        let mut ex_table_buf = vec![0u8; (addr___stop___ex_table - addr___start___ex_table) as usize];
        guest_mem
            .read_slice(
                &mut ex_table_buf,
                GuestAddress(addr___start___ex_table - __START_KERNEL_MAP + phys_offset),
            )
            .expect("Couldn't read ex_table from guest mem");

        let extable_ent_size = std::mem::size_of::<extable::ExTableEntry>();
        let mut start_ex_table = vec![extable::ExTableEntry::default(); num_entries as usize];


        for i in 0..num_entries as usize{
            
            let p = i*extable_ent_size;
            let mut entry: extable::ExTableEntry = Default::default();
            let mut buf: &[u8] = ex_table_buf[p..p+extable_ent_size]
                .try_into()
                .expect("Couldn't convert extable entry slice");

            entry
                .as_bytes()
                .read_from(0, &mut buf, extable_ent_size).unwrap();
            
            start_ex_table[i]=entry;
        }

        let mut cur_addr = addr___start___ex_table - __START_KERNEL_MAP;

        /*
        * Similar to handle relocations, update each field of each exception table
        * entry if it points to one of the randomized .text.* sections
        */
        for i in 0..num_entries as usize {

            let insn: i32 = cur_addr as i32 + start_ex_table[i].insn;
            let fixup: i32 = (cur_addr + 4) as i32 + start_ex_table[i].fixup;
            let handler: i32 = (cur_addr + 8) as i32 + start_ex_table[i].handler;

            /* check each address to see if it needs adjusting */
            let mut addr = (insn as u64 + __START_KERNEL_MAP) as i64;
            let idx = adjust_address(&mut addr, sections, sections_size, offsets);
            if idx >= 0 {
                let idx = idx as usize;
                let offset = offsets[idx];
                let value = start_ex_table[i].insn as i64 + offset;
                start_ex_table[i].insn = value as i32;
            }

            let mut addr = (fixup as u64 + __START_KERNEL_MAP) as i64;
            let idx = adjust_address(&mut addr, sections, sections_size, offsets);
            if idx >= 0 {
                let idx = idx as usize;
                let offset = offsets[idx];
                let value = start_ex_table[i].fixup as i64 + offset;
                start_ex_table[i].fixup = value as i32;
            }

            let mut addr = (handler as u64 + __START_KERNEL_MAP) as i64;
            let idx = adjust_address(&mut addr, sections, sections_size, offsets);
            if idx >= 0 {
                let idx = idx as usize;
                let offset = offsets[idx];
                let value = start_ex_table[i].handler as i64 + offset;
                start_ex_table[i].handler = value as i32;
            }

            cur_addr += 12;
        }

        //We need to re-sort the exception table because after updating its fields it is no longer sorted
        sort_ex_table(
            &mut start_ex_table,
            num_entries as usize,
            addr___start___ex_table,
        );
        
        let mut ex_table_buf: Vec<u8> = Vec::new();

        for entry in &start_ex_table {
            let mut insn_bytes = (entry.insn).to_le_bytes().to_vec();
            let mut fixup_bytes = (entry.fixup).to_le_bytes().to_vec();
            let mut handler_bytes = (entry.handler).to_le_bytes().to_vec();

            //Append each byte array in correct order
            ex_table_buf.append(&mut insn_bytes);
            ex_table_buf.append(&mut fixup_bytes);
            ex_table_buf.append(&mut handler_bytes);

        }

        //Write exception table back to guest memory
        guest_mem
            .write(
                &ex_table_buf,
                GuestAddress(addr___start___ex_table - __START_KERNEL_MAP + phys_offset),
            )
            .expect("Couldn't write ex_table back to guest mem");
    }
    Ok(())
}

fn is_orc_unwind(
    addr: i64, 
) -> bool {
    unsafe{
        #[allow(non_snake_case)]
        let addr___start_orc_unwind_ip = ADDR__START_ORC_UNWIND_IP;
        #[allow(non_snake_case)]
        let addr___stop_orc_unwind_ip = ADDR__STOP_ORC_UNWIND_IP;

        if addr >= addr___start_orc_unwind_ip as i64 && addr < addr___stop_orc_unwind_ip as i64 {
            return true;
        }
    }
    false
}

fn is_text(
    addr: i64, 
) -> bool {
    unsafe {
        #[allow(non_snake_case)]
        let addr__stext = ADDR_STEXT;
        #[allow(non_snake_case)]
        let addr__etext = ADDR_ETEXT;
        #[allow(non_snake_case)]
        let addr__sinittext = ADDR_SINITTEXT;
        #[allow(non_snake_case)]
        let addr__einittext = ADDR_EINITTEXT;

        let temp = addr as u64;
        if (temp >= addr__stext && temp < addr__etext)
            || (temp >= addr__sinittext && temp < addr__einittext)
        {
            return true;
        }
    }
    false
}

pub fn is_percpu_addr(
    pc: i64, 
    offset: i64, 
) -> bool {
    let address = pc + offset + 4;
    let ptr = address as u64;

    unsafe{
        if ptr >= ADDR_PERCPU_START && ptr < ADDR_PERCPU_END {
            return true;
        }
    }

    false
}

pub fn adjust_relative_offset(
    pc: i64,
    value: &mut i64,
    sections: &Vec<elf::Elf64_Shdr>,
    sections_size: usize,
    offsets: &Vec<i64>,
    idx: i32,
) -> Result<()> {
    // From Linux:
    /*
     * sometimes we are updating a relative offset that would
     * normally be relative to the next instruction (such as a call).
     * In this case to calculate the target, you need to add 32bits to
     * the pc to get the next instruction value. However, sometimes
     * targets are just data that was stored in a table such as ksymtab
     * or cpu alternatives. In this case our target is not relative to
     * the next instruction.
     */

    let mut address = match !is_text(pc) {
        true => pc + *value,
        false => pc + *value + 4,
    };

    if is_orc_unwind(pc,) {
        return Ok(());
    }

    let i = adjust_address(&mut address, sections, sections_size, offsets);

    if i >= 0 {
        let offset = offsets[i as usize];
        *value += offset;
    }

    if idx >= 0 {
        let offset = offsets[idx as usize];
        *value -= offset;
    }

    Ok(())
}

fn cmp_section_addr(ptr: u64, s: &elf::Elf64_Shdr) -> i32 {
    let end = s.sh_addr + s.sh_size;
    //Does the given address lie inside the given section?
    if ptr >= s.sh_addr && ptr < end {
        return 0i32;
    }

    if ptr < s.sh_addr {
        return -1i32;
    }

    return 1;
}

pub fn adjust_address(
    address: &mut i64,
    sections: &Vec<elf::Elf64_Shdr>,
    sections_size: usize,
    offsets: &Vec<i64>,
) -> i32 {
    /*
     * Search the sections that were randomized to see if an address
     * points to something inside that section, and adjust the address
     * by the offset applied to the section during randomization.
     */

    let addr = *address as u64;
    let mut base = 0;
    let mut m = -1i32;
    // Try to do direct copy from C

    let mut num = sections_size;
    //Already verified that the number of sections are correct

    //Linux binary search from lib/bsearch.c
    while num > 0 {
        let pivot = base + (num >> 1);

        let result = cmp_section_addr(addr, &sections[pivot]);

        if result == 0 {
            m = pivot as i32;
            break;
        }

        if result > 0 {
            base = pivot + 1;
            num -= 1;
        }

        num = num >> 1;
    }

    if m >= 0 {
        let offset = offsets[m as usize];
        *address += offset;
        return m;
    } else {
        return -1;
    }
}

pub fn post_relocations_cleanup(
    guest_mem: &GuestMemoryMmap,
    sections: &Vec<elf::Elf64_Shdr>,
    sections_size: usize,
    offsets: &Vec<i64>,
    phys_offset: u64,
) -> Result<()> {
    //update_ex_table calls sort_ex_table
    update_ex_table(
        guest_mem,
        sections,
        sections_size,
        offsets,
        phys_offset,
    )?;

    Ok(())
}

fn move_text<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    num_sections: usize,
    offsets: &mut Vec<i64>,
    sections: &Vec<elf::Elf64_Shdr>,
    text: &elf::Elf64_Shdr,
    phdr: &elf::Elf64_Phdr,
    dest: u64,
) -> Result<()>
where
    F: Read + Seek,
{
    /*
     * Shuffle the .text.* section and lay them out contiguously in guest_mem
     */

    // source + text->sh_offset
    kernel_image
        .seek(SeekFrom::Start(text.sh_offset))
        .map_err(|_| Error::SeekKernelStart)?;
    // Dest in linux
    let mem_offset = GuestAddress(dest + 0x000000000100_0000);

    guest_mem
        .read_from(mem_offset, kernel_image, text.sh_size as usize)
        .map_err(|_| Error::ReadKernelImage)?;

    let mut copy_bytes = text.sh_size;
    let mut dest = dest + text.sh_size;
    let mut adjusted_addr = text.sh_addr + text.sh_size;
    let mut index_list = vec![0; num_sections];
    let mut text_copy = vec![0u8; phdr.p_filesz as usize];

    kernel_image
        .seek(SeekFrom::Start(phdr.p_offset))
        .map_err(|_| Error::SeekKernelStart)?;

    /*
     * Ended up doing this copy because its faster than seeking to a position
     * in the kernel image each time we want to copy a section. Storing every
     * section in a buffer brought the boot time down ~10ms
     */
    kernel_image
        .read_exact(&mut text_copy)
        .expect("Couldn't read text sections to buffer");

    /*
     * Create a list of indices, shuffle them, and use the shuffled indices
     * to access the vector of sections out of order, but lay them out
     * in memory in the order we encounter them.
     */
    for i in 0..num_sections {
        index_list[i] = i;
    }

    let mut rng = rand::thread_rng();
    index_list.shuffle(&mut rng);

    for i in 0..num_sections {
        let s = sections[index_list[i]];

        let aligned_addr = align(adjusted_addr, s.sh_addralign)?;
        let pad_bytes = aligned_addr - adjusted_addr;

        //Create vec of pad bytes to write to guest mem to fill spaces between aligned sections
        let buf = vec![0xccu8; pad_bytes as usize];
        guest_mem
            .write(&buf, GuestAddress(dest + 0x000000000100_0000))
            .map_err(|_| Error::WriteGuestMemoryMmap)?;

        dest = align(dest, s.sh_addralign)?;

        let start_pos = (s.sh_offset - phdr.p_offset) as usize;
        let mut buf = text_copy[start_pos..start_pos + s.sh_size as usize].to_vec();

        guest_mem
            .write(&mut buf, GuestAddress(dest + 0x000000000100_0000))
            .expect("Couldn't write .text.* section to guest memory");

        //Update variables
        dest += s.sh_size;
        copy_bytes += s.sh_size + pad_bytes;
        adjusted_addr = aligned_addr + s.sh_size;

        /*
         * The kernel saves the sections' offsets in the sh_offset field
         * but the offsets are signed so save them to a list
         */
        offsets[index_list[i]] = aligned_addr as i64 - s.sh_addr as i64;
    }

    // Moving the rest of the text segment
    kernel_image
        .seek(SeekFrom::Start(text.sh_offset + copy_bytes))
        .map_err(|_| Error::SeekKernelImage)?;

    guest_mem
        .read_from(
            GuestAddress(dest + 0x000000000100_0000),
            kernel_image,
            (phdr.p_filesz - copy_bytes) as usize,
        )
        .map_err(|_| Error::ReadKernelImage)?;

    Ok(())
}

//In linux this is a macro
fn get_sym(addr: &mut u64, sym: &elf::Elf64_Sym, name: &str, strtab: &Vec<u8>) -> Result<()> {
    if *addr == 0 {
        let sname_start = sym.st_name as usize;
        let mut sname_end = sname_start;
        //Start at index into the string table and iterate until null byte
        for b in strtab[sname_start as usize..].iter() {
            if *b == 0u8 {
                break;
            }
            sname_end += 1;
        }

        //Convert bytes to string
        let sname: &str = match std::str::from_utf8(&strtab[sname_start..sname_end]) {
            Ok(v) => v,
            Err(e) => panic!("Couldn't read section name: {}", e),
        };

        if sname.eq(name) {
            *addr = sym.st_value;
        }
    }

    Ok(())
}

fn parse_symtab(
    symtab: &Vec<elf::Elf64_Sym>,
    strtab: &Vec<u8>,
) -> Result<()> {
    if symtab.is_empty() || strtab.is_empty() {
        return Ok(());
    }
    unsafe {
        let mut all_addr = [
            (&mut ADDR_STEXT, _STEXT),
            (&mut ADDR_ETEXT, _ETEXT),
            (&mut ADDR_SINITTEXT, _SINITTEXT),
            (&mut ADDR_EINITTEXT, _EINITTEXT),
            (&mut ADDR__START_ORC_UNWIND_IP, __START_ORC_UNWIND_IP),
            (&mut ADDR__STOP_ORC_UNWIND_IP, __STOP_ORC_UNWIND_IP),
            (&mut ADDR__START_ORC_UNWIND, __START_ORC_UNWIND),
            (&mut ADDR__START___EX_TABLE, __START___EX_TABLE),
            (&mut ADDR__STOP___EX_TABLE, __STOP___EX_TABLE),
        ];
    
        //Search through the symbol table to find the symbols we want by grabbing the symbol names
        for s in symtab {
            if s.st_name == 0 {
                continue;
            }

            for i in 0..all_addr.len() {
                let ent = &mut all_addr[i];
                get_sym(ent.0, &s, ent.1, strtab)?;
            }
        }
    }

    Ok(())
}

pub fn layout_randomized_image<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    start_address: u64,
    ehdr: &elf::Elf64_Ehdr,
    phrds: &Vec<elf::Elf64_Phdr>,
    sections: &mut Vec<elf::Elf64_Shdr>,
    sections_size: &mut usize,
    offsets: &mut Vec<i64>,
    phys_offset: u64,
) -> Result<()>
where
    F: Read + Seek,
{
    /*
     * Parse the kernel image for .text.* sections to be shuffled
     * and save important symbols that will be used to compare
     * addresses during relocations
     */

    let mut shdr: elf::Elf64_Shdr = Default::default();
    let mut symtab: Vec<elf::Elf64_Sym> = Vec::new();
    let mut strtab: Vec<u8> = Vec::new();
    let mut text: elf::Elf64_Shdr = Default::default();
    let mut percpu: elf::Elf64_Shdr = Default::default();
    let mut num_sections: usize = 0;
    let mut found_text = false;
    let mut found_percpu = false;

    // read the first section header
    let mut shnum: u64 = ehdr.e_shnum as u64;
    let mut shstrndx: u64 = u64::from(ehdr.e_shstrndx);
    let offset = ehdr.e_shoff;

    // Get number of sections and index of the section name string table
    if shnum == u64::from(elf::SHN_UNDEF) || shstrndx == u64::from(elf::SHN_XINDEX) {

        shdr.as_bytes()
            .read_from(offset as usize, kernel_image, std::mem::size_of::<elf::Elf64_Shdr>())
            .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF section header"))?;

        if shnum as u32 == elf::SHN_UNDEF {
            shnum = shdr.sh_size;
        }
        if shstrndx as u32 == elf::SHN_XINDEX {
            shstrndx = u64::from(shdr.sh_link)
        }
    }

    kernel_image
        .seek(SeekFrom::Start(offset))
        .map_err(|_| Error::SeekKernelImage)?;

    //Read all sections headers into vector
    let sechdr_size = std::mem::size_of::<elf::Elf64_Shdr>();
    let mut sechdrs_bytes = vec![0u8; sechdr_size * shnum as usize];
    let mut sechdrs: Vec<elf::Elf64_Shdr> = vec![Default::default(); shnum as usize];
    kernel_image
        .read_exact(&mut sechdrs_bytes)
        .map_err(|_| Error::ReadKernelDataStruct("Failed to read sechdrs"))?;

    for i in 0..shnum as usize{
        
        let p = i*sechdr_size;
        let mut sechdr: elf::Elf64_Shdr = Default::default();
        let mut buf: &[u8] = sechdrs_bytes[p..p+sechdr_size]
            .try_into()
            .expect("Couldn't convert section header slice");

        sechdr
            .as_bytes()
            .read_from(0, &mut buf, sechdr_size).unwrap();
       
        sechdrs[i]=sechdr;
    }

    //Initialize vector for .text.* sections
    sections.resize(shnum as usize, Default::default());

    // get string table
    let s = sechdrs[shstrndx as usize];

    kernel_image
        .seek(SeekFrom::Start(s.sh_offset))
        .map_err(|_| Error::SeekKernelImage)?;

    let mut secstrings = vec![0u8; s.sh_size as usize];
    // read string table into byte vector
    kernel_image
        .read_exact(&mut secstrings)
        .map_err(|_| Error::ReadKernelImage)?;

    /*
     * now we need to walk through the section headers and collect the
     * sizes of the .text sections to be randomized.
     */
    for i in 0..shnum as usize {
        let s = sechdrs[i];
        let sname: usize = s.sh_name as usize;
        let mut sname_end = sname;

        //Start at section's offset into the string table and iterate until null byte to get section name
        for b in secstrings[sname..].iter() {
            if *b == 0u8 {
                break;
            }
            sname_end += 1;
        }

        //Convert bytes to string
        let sname = match std::str::from_utf8(&secstrings[sname..sname_end]) {
            Ok(v) => v,
            Err(e) => panic!("Couldn't read section name: {}", e),
        };

        //Need the symbol table to grab important addresses later
        if s.sh_type == elf::SHT_SYMTAB {
            //Save symtab to Vec of symbols
            if !symtab.is_empty() {
                panic!("Unexpected duplicate symtab");
            }
            let sym_size = std::mem::size_of::<elf::Elf64_Sym>();
            let num_syms = s.sh_size / sym_size as u64;

            kernel_image
                .seek(SeekFrom::Start(s.sh_offset))
                .map_err(|_| Error::SeekKernelImage)?;

            let mut symtab_bytes = vec![0u8; s.sh_size as usize];
            symtab = vec![Default::default(); num_syms as usize];
            kernel_image
                .read_exact(&mut symtab_bytes)
                .map_err(|_| Error::ReadKernelDataStruct("Failed to read symtab"))?;

            for i in 0..num_syms as usize{
                
                let p = i*sym_size;
                let mut sym: elf::Elf64_Sym = Default::default();
                let mut buf: &[u8] = symtab_bytes[p..p+sym_size]
                    .try_into()
                    .expect("Couldn't convert extable entry slice");

                sym
                    .as_bytes()
                    .read_from(0, &mut buf, sym_size).unwrap();
                
                symtab[i]=sym;
            }

            continue;
        }

        if s.sh_type == elf::SHT_STRTAB && i != shstrndx as usize {
            if !strtab.is_empty() {
                panic!("Unexpected duplicate strtab");
            }

            //strtab is passed to parse_symtab and symbol names are parsed there
            strtab = vec![0u8; s.sh_size as usize];
            kernel_image
                .seek(SeekFrom::Start(s.sh_offset))
                .map_err(|_| Error::SeekKernelImage)?;
            kernel_image
                .read_exact(&mut strtab)
                .map_err(|_| Error::ReadKernelImage)?;
        }

        if sname.eq(".text") {
            if found_text {
                panic!("Unexpected duplicate .text section");
            }
            found_text = true;
            text = s;
            continue;
        }

        if sname.eq(".data..percpu") {
            found_percpu = true;
            percpu = s;
            continue;
        }

        if (s.sh_flags & elf::SHF_ALLOC as u64) == 0
            || (s.sh_flags & elf::SHF_EXECINSTR as u64) == 0
            || !sname.starts_with(".text")
        {
            continue;
        }

        //If s is a .text.* section, save it so we can shuffle them later
        sections[num_sections] = s;
        num_sections += 1;
    }
    *sections_size = num_sections;
    /*
     * Initialize list of offsets for each .text.*
     * Each offset is the difference between the address the .text.* started at and
     * the address it was relocated to after shuffling
     */

    offsets.resize(num_sections, 0i64);

    //Save all the addresses we need for later in a hashmap
    parse_symtab(&symtab, &strtab)?;

    /*
     * Layout the kernel in guest memory the same way we did before fgkaslr
     * was implemented, but when we get to the .text phdr we shuffle the .text.*
     * sections and lay them out contiguously. Everything else is laid out
     * as it normally would.
     */
    for phdr in phrds {
        if phdr.p_type == elf::PT_LOAD {
            if (phdr.p_align % 0x200_000) != 0 {
                panic!("Alignment of LOAD segment isn't multiple of 2MB");
            }

            let dest = phdr.p_paddr - 0x000000000100_0000 + phys_offset;

            //Randomize the text sections
            if found_text && phdr.p_offset == text.sh_offset {
                move_text(
                    guest_mem,
                    kernel_image,
                    num_sections,
                    offsets,
                    &sections,
                    &text,
                    &phdr,
                    dest,
                )?;
            } else {
                if found_percpu && phdr.p_offset == percpu.sh_offset {
                    unsafe {
                        ADDR_PERCPU_START = percpu.sh_addr;
                        ADDR_PERCPU_END = ADDR_PERCPU_START + phdr.p_filesz;
                    }
                }
                kernel_image
                    .seek(SeekFrom::Start(phdr.p_offset))
                    .map_err(|_| Error::SeekKernelStart)?;
                let mem_offset = GuestAddress(dest + 0x000000000100_0000);

                if mem_offset.raw_value() < start_address {
                    return Err(Error::InvalidProgramHeaderAddress);
                }

                guest_mem
                    .read_from(mem_offset, kernel_image, phdr.p_filesz as usize)
                    .map_err(|_| Error::ReadKernelImage)?;
            }
        }
    }

    Ok(())
}