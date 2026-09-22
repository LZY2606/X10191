package compass.dwarf

import compass.elf.ElfFile
import compass.elf.Reader

/** The set of debug sections a parse may consult. Missing sections are null;
 *  consumers record an issue and keep going with whatever remains trustworthy. */
class DwarfSections(
    val info: ByteArray?,
    val abbrev: ByteArray?,
    val line: ByteArray?,
    val str: ByteArray?,
    val strOffsets: ByteArray?,
    val lineStr: ByteArray?,
    val addr: ByteArray?,
    val ranges: ByteArray?,
    val rnglists: ByteArray?,
    val bigEndian: Boolean,
) {
    fun readerOf(section: ByteArray?) = section?.let { Reader(it, bigEndian = bigEndian) }

    companion object {
        fun from(elf: ElfFile): DwarfSections {
            fun s(name: String) = elf.section(name)?.data
            return DwarfSections(
                info = s(".debug_info"),
                abbrev = s(".debug_abbrev"),
                line = s(".debug_line"),
                str = s(".debug_str"),
                strOffsets = s(".debug_str_offsets"),
                lineStr = s(".debug_line_str"),
                addr = s(".debug_addr"),
                ranges = s(".debug_ranges"),
                rnglists = s(".debug_rnglists"),
                bigEndian = elf.bigEndian,
            )
        }
    }
}

class UnknownForm(val form: Long) : Exception("unknown DW_FORM 0x${form.toString(16)}")
class BadReference(msg: String) : Exception(msg)
