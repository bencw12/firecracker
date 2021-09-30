// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Helper for loading a kernel image in the guest memory.

extern crate rand;
use rand::thread_rng;
use rand::Rng;

use std::ffi::CString;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::convert::{TryFrom, TryInto};
use std::fs::File;

use super::cmdline::Error as CmdlineError;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use arch::x86_64::layout::__START_KERNEL_MAP;
use utils::time::TimestampUs;
use logger::info;

#[allow(non_camel_case_types)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Add here any other architecture that uses as kernel image an ELF file.
mod elf;
mod extable;
mod fgkaslr;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl ByteValued for elf::Elf64_Ehdr {}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl ByteValued for elf::Elf64_Phdr {}

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    InvalidElfMagicNumber,
    InvalidEntryAddress,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderAddress,
    ReadKernelDataStruct(&'static str),
    ReadKernelImage,
    SeekKernelStart,
    SeekKernelImage,
    SeekProgramHeader,
    SeekRelocsFile, 
    ReadRelocsFile,
    WriteGuestMemoryMmap,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidEntryAddress => "Invalid entry address found in ELF header",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::InvalidProgramHeaderAddress => "Invalid ELF program header address",
                Error::ReadKernelDataStruct(ref e) => e,
                Error::ReadKernelImage => "Failed to write kernel image to guest memory",
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
                Error::SeekRelocsFile => "KASLR: Failed to seek to offset of relocs file",
                Error::ReadRelocsFile => "Failed to read from relocs file",
                Error::WriteGuestMemoryMmap => "BCWH: Failed to write bytes to guest memory",
            }
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// DJW: this is caclulated the same as in arch/x86/boot/compressed/kaslr.c
// phys is simplified from what linux does but experimentally should work
pub fn rand_addr(img_size: u64, minimum: u64, maximum: u64, align: u64) -> std::io::Result<u64> {
    let asize = (img_size + (align - 1)) - ((img_size + align - 1) % align);
    let slots: u64 = (maximum - minimum - asize) / align + 1;
    let randslot: u64 = thread_rng().gen_range(0, slots);

    Ok((randslot * align) + minimum)
}

// do relocs for the virtual offset if a relocs file is provided
fn handle_relocations(
    guest_mem: &GuestMemoryMmap,
    relocs_path: &Option<File>,
    virt_offset: u32,
    phys_offset: u32,
    sections: &Vec<elf::Elf64_Shdr>,
    sections_size: usize,
    offsets: &Vec<i64>,
) -> Result<()> {
    
    // BCWH: This is safe because we checked if None in load_kernel
    let mut relocs_path = relocs_path.as_ref().unwrap();
   
    let img_size = relocs_path
        .seek(SeekFrom::End(0))
        .expect("Couldn't get relocs file length");

    let mut p = (img_size - 4) as usize;

    let mut contents = vec![0u8; img_size as usize];

    relocs_path
        .seek(SeekFrom::Start(0))
        .expect("Couldn't seek to start of relocs file");

    relocs_path
        .read_exact(&mut contents)
        .map_err(|_| Error::ReadRelocsFile)?;
    // 32-bit 
    loop {
        let buf = contents[p..p+4]
            .try_into()
            .expect("Couldn't convert slice");

        let reloc = i32::from_le_bytes(buf);
        let mut extended = i64::from(reloc);

        p -= 4;
        if extended != 0 {
            fgkaslr::adjust_address(&mut extended, sections, sections_size, offsets);
            
            extended -= __START_KERNEL_MAP as i64; 
            extended += phys_offset as i64;
            let ptr = GuestAddress(extended as u64);
            let value_buf = &mut [0u8; 4];

            guest_mem
                .read_slice(value_buf, ptr)
                .expect("Can't read 32-bit reloc");
            let mut value = i32::from_le_bytes(*value_buf) as i64;

            fgkaslr::adjust_address(&mut value, sections, sections_size, offsets);

            value += virt_offset as i64;
            let temp = value as u32;

            guest_mem
                .write(&temp.to_le_bytes(), ptr)
                .expect("Can't write 32-bit reloc");
        } else {
            break;
        }
    }
    // 32 bit inverse 
    loop {
        let buf = contents[p..p+4]
            .try_into()
            .expect("Couldn't convert slice");

        let mut extended = i32::from_le_bytes(buf) as i64;
        let reloc = i32::from_le_bytes(buf) as i64;

        p -= 4;
        if extended != 0 {
            let idx = 
                fgkaslr::adjust_address(&mut extended, sections, sections_size, offsets);
            
            extended -= __START_KERNEL_MAP as i64;
            extended += phys_offset as i64; 
            let ptr = GuestAddress(extended as u64);
            let value_buf = &mut [0u8; 4];

            guest_mem
                .read_slice(value_buf, ptr)
                .expect("Can't read 32-bit inv reloc");
            let mut value = i32::from_le_bytes(*value_buf) as i64;
            let oldvalue = value;

            fgkaslr::adjust_relative_offset(
                reloc, 
                &mut value, 
                sections, 
                sections_size,
                offsets,
                idx,
            )?;

            if fgkaslr::is_percpu_addr(
                reloc, 
                oldvalue, 
            ) {
                value -= virt_offset as i64;
            }
            let temp = value as u32;
            guest_mem
                .write(&temp.to_le_bytes() , ptr)
                .expect("Can't write 32-bit inv reloc");
        } else {
            break;
        }
    }
    // 64-bit
    loop {
        let buf = contents[p..p+4]
            .try_into()
            .expect("Couldn't convert slice");

        let mut extended = i32::from_le_bytes(buf) as i64;

        if extended != 0 {
            fgkaslr::adjust_address(
                &mut extended,
                sections, 
                sections_size,
                offsets,
            );
            
            extended -= __START_KERNEL_MAP as i64; 
            extended += phys_offset as i64;
            let ptr = GuestAddress(extended as u64);
            let value_buf = &mut [0u8; 8];

            guest_mem
                .read_slice(value_buf, ptr)
                .expect("Can't read 64-bit reloc");
            let mut value = i64::from_le_bytes(*value_buf);

            fgkaslr::adjust_address(
                &mut value,
                sections,
                sections_size,
                offsets,
            );

            value += 
                i64::try_from(virt_offset).expect("Couldn't convert virt_offset from u32 to i64");
            let temp = value as u64;

            guest_mem
                .write(&temp.to_le_bytes(), ptr)
                .expect("Can't write 64-bit reloc");
        } else {
            break;
        }
        p -= 4;
    }

    assert!(p == 0);
    Ok(())
}

fn layout_image<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    start_address: u64,
    phdrs: &Vec<elf::Elf64_Phdr>,
    phys_offset: u64,
) -> Result<()>
where
    F: Read + Seek,
{
    for phdr in phdrs {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = GuestAddress(phdr.p_paddr + phys_offset);
        if mem_offset.raw_value() < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        guest_mem
            .read_from(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    Ok(())
}

/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - For x86_64, this is the start of the high memory. Kernel should reside above it.
///
/// Returns the entry address of the kernel.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn load_kernel<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    relocs_file: &Option<File>,
    start_address: u64,
) -> Result<GuestAddress>
where
    F: Read + Seek,
{

    let parse_elf_time = TimestampUs::default().time_us;

    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;
    let img_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    let rando_time = TimestampUs::default().time_us;

    let (phys_offset, virt_offset, do_kaslr) = match relocs_file {
        None => (0u64, 0u64, false),
        _ => (
            0,
            rand_addr(
                img_size, 
                0x0100_0000,
                1024*1024*1024,
                0x200_000,
            )
            .expect("Couldn't get virtual KASLR offset"),
            true,
        ),
    };
    
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;

    let mut ehdr = elf::Elf64_Ehdr::default();
    ehdr.as_bytes()
        .read_from(0, kernel_image, mem::size_of::<elf::Elf64_Ehdr>())
        .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF header"))?;

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
        return Err(Error::InvalidElfMagicNumber);
    }
    if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianElfOnLittle);
    }
    if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }
    if ehdr.e_entry < start_address {
        return Err(Error::InvalidEntryAddress);
    }

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdr_sz = mem::size_of::<elf::Elf64_Phdr>();
    let mut phdrs: Vec<elf::Elf64_Phdr> = vec![];
    for _ in 0usize..ehdr.e_phnum as usize {
        let mut phdr = elf::Elf64_Phdr::default();
        phdr.as_bytes()
            .read_from(0, kernel_image, phdr_sz)
            .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF program header"))?;
        phdrs.push(phdr);
    }

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = GuestAddress(phdr.p_paddr);
        if mem_offset.raw_value() < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        guest_mem
            .read_from(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    if do_kaslr {

        let mut sections: Vec<elf::Elf64_Shdr> = Vec::new();
        let mut sections_size: usize = 0;
        let mut offsets: Vec<i64> = Vec::new();


        fgkaslr::layout_randomized_image(
            &guest_mem,
            kernel_image,
            start_address,
            &ehdr,
            &phdrs,
            &mut sections,
            &mut sections_size,
            &mut offsets,
            phys_offset,
        )?;
        let parse_elf_time = TimestampUs::default().time_us - parse_elf_time;

        info!("parse_elf: {}", parse_elf_time);


        let relocs_time = TimestampUs::default().time_us;

        handle_relocations(
            guest_mem, 
            relocs_file, 
            u32::try_from(virt_offset).expect("Couldn't convert virtual offset from u64 to u32"),
            u32::try_from(phys_offset).expect("Couldn't convert physical offset from u64 to u32"),
            &sections, 
            sections_size,
            &mut offsets, 
        )?;
        let relocs_time = TimestampUs::default().time_us - relocs_time;
        info!("handle_relocations: {}", relocs_time);

        let post_relocs_time = TimestampUs::default().time_us;

        fgkaslr::post_relocations_cleanup(
            &guest_mem, 
            &sections,
            sections_size,
            &mut offsets,
            phys_offset,
        )?;

        let rando_time = TimestampUs::default().time_us - rando_time;
        info!("in-monitor-randomization: {}", rando_time);

        let post_relocs_time = TimestampUs::default().time_us - post_relocs_time;
        info!("post_relocations_cleanup: {}", post_relocs_time);
    } else {
        layout_image(
            &guest_mem, 
            kernel_image, 
            start_address, 
            &phdrs,
            phys_offset,
        )?;
    }

    Ok(GuestAddress(ehdr.e_entry))
}

#[cfg(target_arch = "aarch64")]
pub fn load_kernel<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    start_address: u64,
) -> Result<GuestAddress>
where
    F: Read + Seek,
{
    /* Kernel boot protocol is specified in the kernel docs
    Documentation/arm/Booting and Documentation/arm64/booting.txt.

    ======aarch64 kernel header========
    u32 code0;			/* Executable code */
    u32 code1;			/* Executable code */
    u64 text_offset;		/* Image load offset, little endian */
    u64 image_size;		/* Effective Image size, little endian */
    u64 flags;			/* kernel flags, little endian */
    u64 res2	= 0;		/* reserved */
    u64 res3	= 0;		/* reserved */
    u64 res4	= 0;		/* reserved */
    u32 magic	= 0x644d5241;	/* Magic number, little endian, "ARM\x64" */
    u32 res5;			/* reserved (used for PE COFF offset) */
    ====================================
     */
    const AARCH64_KERNEL_LOAD_ADDR: u64 = 0x80000;
    const AARCH64_MAGIC_NUMBER: u32 = 0x644d_5241;
    const AARCH64_MAGIC_OFFSET_HEADER: u64 =
        2 * mem::size_of::<u32>() as u64 + 6 * mem::size_of::<u64>() as u64; // This should total 56.
    const AARCH64_TEXT_OFFSET: u64 = 2 * mem::size_of::<u32>() as u64;
    let mut kernel_load_offset = AARCH64_KERNEL_LOAD_ADDR;

    /* Look for the magic number inside the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_MAGIC_OFFSET_HEADER))
        .map_err(|_| Error::SeekKernelImage)?;
    let mut magic_number: u32 = 0;
    magic_number
        .as_bytes()
        .read_from(0, kernel_image, mem::size_of::<u32>())
        .map_err(|_| Error::ReadKernelDataStruct("Failed to read magic number"))?;
    if u32::from_le(magic_number) != AARCH64_MAGIC_NUMBER {
        return Err(Error::InvalidElfMagicNumber);
    }

    /* Look for the `text_offset` from the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_TEXT_OFFSET)) // This should total 8.
        .map_err(|_| Error::SeekKernelImage)?;
    let mut hdrvals: [u64; 2] = [0; 2];
    hdrvals
        .as_bytes()
        .read_from(0, kernel_image, 2 * mem::size_of::<u64>())
        .map_err(|_| Error::ReadKernelDataStruct("Failed to read kernel offset and image size"))?;
    /* Following the boot protocol mentioned above. */
    if u64::from_le(hdrvals[1]) != 0 {
        kernel_load_offset = u64::from_le(hdrvals[0]);
    }
    /* Get the total size of kernel image. */
    let kernel_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    /* Last `seek` will leave the image with the cursor at its end, rewind it to start. */
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;

    kernel_load_offset += start_address;
    guest_mem
        .read_from(
            GuestAddress(kernel_load_offset),
            kernel_image,
            kernel_size as usize,
        )
        .map_err(|_| Error::ReadKernelImage)?;

    Ok(GuestAddress(kernel_load_offset))
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line as CString.
pub fn load_cmdline(
    guest_mem: &GuestMemoryMmap,
    guest_addr: GuestAddress,
    cmdline: &CString,
) -> std::result::Result<(), CmdlineError> {
    let raw_cmdline = cmdline.as_bytes_with_nul();
    if raw_cmdline.len() <= 1 {
        return Ok(());
    }

    let cmdline_last_addr = guest_addr
        .checked_add(raw_cmdline.len() as u64 - 1)
        .ok_or(CmdlineError::CommandLineOverflow)?; // Extra for null termination.

    if cmdline_last_addr > guest_mem.last_addr() {
        return Err(CmdlineError::CommandLineOverflow);
    }

    guest_mem
        .write_slice(raw_cmdline, guest_addr)
        .map_err(|_| CmdlineError::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cmdline::Cmdline;
    use super::*;
    use std::io::Cursor;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const MEM_SIZE: usize = 0x18_0000;

    fn create_guest_mem() -> GuestMemoryMmap {
        vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0x0), MEM_SIZE)], false)
            .unwrap()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_elf.bin").to_vec()
    }

    #[cfg(target_arch = "aarch64")]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_pe.bin").to_vec()
    }

    #[test]
    // Tests that loading the kernel is successful on different archs.
    fn test_load_kernel() {
        let gm = create_guest_mem();
        let image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let load_addr = 0x10_0000;
        #[cfg(target_arch = "aarch64")]
        let load_addr = 0x8_0000;
        assert_eq!(
            Ok(GuestAddress(load_addr)),
            load_kernel(&gm, &mut Cursor::new(&image), 0)
        );
    }

    #[test]
    fn test_load_kernel_no_memory() {
        let gm =
            vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0x0), 4096)], false)
                .unwrap();
        let image = make_test_bin();
        assert_eq!(
            Err(Error::ReadKernelImage),
            load_kernel(&gm, &mut Cursor::new(&image), 0)
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_load_bad_kernel() {
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image.truncate(56);
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[test]
    fn test_bad_kernel_magic() {
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let offset = 0x1;
        #[cfg(target_arch = "aarch64")]
        let offset = 0x38;
        bad_image[offset] = 0x33;
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_endian() {
        // Only little endian is supported.
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image[0x5] = 2;
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_phsize() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image[0x36] = 0x10;
        assert_eq!(
            Err(Error::InvalidProgramHeaderSize),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_invalid_entry() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let bad_image = make_test_bin();
        assert_eq!(
            Err(Error::InvalidEntryAddress),
            load_kernel(&gm, &mut Cursor::new(&bad_image), std::u64::MAX)
        );
    }

    #[test]
    fn test_cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress((MEM_SIZE - 5) as u64);
        let mut cmdline = Cmdline::new(10);
        cmdline.insert_str("12345").unwrap();
        let cmdline = cmdline.as_cstring().unwrap();
        assert_eq!(
            Err(CmdlineError::CommandLineOverflow),
            load_cmdline(&gm, cmdline_address, &cmdline)
        );
    }

    #[test]
    fn test_cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        let mut cmdline = Cmdline::new(10);
        cmdline.insert_str("1234").unwrap();
        let cmdline = cmdline.as_cstring().unwrap();
        assert_eq!(Ok(()), load_cmdline(&gm, cmdline_address, &cmdline));
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }
}
