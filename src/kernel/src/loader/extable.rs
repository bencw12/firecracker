#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct exception_table_entry {
    pub insn: i32,
    pub fixup: i32,
    pub handler: i32,
}
impl Clone for exception_table_entry {
    fn clone(&self) -> Self {
        *self
    }
}
pub type ExTableEntry = exception_table_entry;
