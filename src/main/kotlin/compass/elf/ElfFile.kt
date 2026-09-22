package compass.elf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException
import compass.dwarf.Section

data class ProgramSegment(val type: Long, val offset: Long, val vaddr: Long, val paddr: Long, val filesz: Long, val memsz: Long, val flags: Long, val align: Long)

/**
 * Minimal ELF reader: only the ELF header, section headers and program headers.
 * Supports ELF32/ELF64, little/big endian. Keeps the raw file bytes so section
 * byte digests can be reproduced later.
 */
class ElfFile(val bytes: ByteArray, val fileName: String = "") {
    val littleEndian: Boolean
    val elfClass: Int // 1 = 32-bit, 2 = 64-bit
    val machine: Int
    val entry: Long
    val sections: List<Section>
    val segments: List<ProgramSegment>
    val sectionByName: Map<String, Section>

    init {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) {
            throw DwarfParseException("not an ELF file: bad magic in $fileName")
        }
        elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw DwarfParseException("bad EI_CLASS ${bytes[4]}")
        val dataEncoding = bytes[5].toInt()
        littleEndian = dataEncoding == 1
        if (!littleEndian && dataEncoding != 2) throw DwarfParseException("bad EI_DATA $dataEncoding")

        val c = Cursor(bytes, 0, bytes.size, 16, littleEndian)
        val (eType, eMachine, _eVersion) = Triple(c.u16(), c.u16(), c.u32())
        machine = eMachine
        entry = if (elfClass == 2) c.u64() else c.u32()

        if (elfClass == 2) {
            val phoff = c.u64(); val shoff = c.u64(); c.u32() // flags
            val ehsize = c.u16(); val phentsize = c.u16(); val phnum = c.u16()
            val shentsize = c.u16(); val shnum = c.u16(); val shstrndx = c.u16()
            ehsize; // read for completeness
            segments = readPh64(phoff, phentsize, phnum)
            sections = readSh64(shoff, shentsize, shnum)
            attachNames(shstrndx)
        } else {
            val phoff = c.u32(); val shoff = c.u32(); c.u32() // e_flags
            val _ehsize = c.u16(); val phentsize = c.u16(); val phnum = c.u16()
            val shentsize = c.u16(); val shnum = c.u16(); val shstrndx = c.u16()
            segments = readPh32(phoff, phentsize, phnum)
            sections = readSh32(shoff, shentsize, shnum)
            attachNames(shstrndx)
        }
        sectionByName = sections.filter { it.name.isNotEmpty() }.associateBy { it.name }
    }

    private fun readSh64(shoff: Long, entsize: Int, count: Int): List<Section> =
        (0 until count).map { i ->
            val c = Cursor(bytes, 0, bytes.size, (shoff + i.toLong() * entsize).toIntExact(), littleEndian)
            val nameIdx = c.u32(); val type = c.u32(); val flags = c.u64()
            val addr = c.u64(); val offset = c.u64(); val size = c.u64()
            c.u32(); val link = c.u32(); val info = c.u64()
            val align = c.u64(); c.u64()
            val data = if (type.toInt() == SHT_NOBITS || offset + size > bytes.size) ByteArray(0)
            else bytes.copyOfRange(offset.toIntExact(), (offset + size).toIntExact())
            Section("", nameIdx, type.toLong() and 0xffffffffL, flags, addr, offset, size, link.toInt(), info, align, data)
        }

    private fun readSh32(shoff: Long, entsize: Int, count: Int): List<Section> =
        (0 until count).map { i ->
            val c = Cursor(bytes, 0, bytes.size, (shoff + i.toLong() * entsize).toIntExact(), littleEndian)
            val nameIdx = c.u32(); val type = c.u32(); val flags = c.u32()
            val addr = c.u32(); val offset = c.u32(); val size = c.u32()
            val link = c.u32(); val info = c.u32(); val align = c.u32(); c.u32()
            val data = if (type.toInt() == SHT_NOBITS || offset + size > bytes.size) ByteArray(0)
            else bytes.copyOfRange(offset.toIntExact(), (offset + size).toIntExact())
            Section("", nameIdx, type.toLong() and 0xffffffffL, flags.toLong() and 0xffffffffL,
                addr.toLong() and 0xffffffffL, offset.toLong() and 0xffffffffL, size.toLong() and 0xffffffffL,
                link.toInt(), info.toLong() and 0xffffffffL, align.toLong() and 0xffffffffL, data)
        }

    private fun attachNames(shstrndx: Int) {
        if (shstrndx == 0 || shstrndx >= sections.size) return
        val strtab = sections[shstrndx].data
        sections.forEach { s ->
            val idx = s.shOffset.toInt()
            if (idx in strtab.indices) {
                var end = idx
            while (end < strtab.size && strtab[end].toInt() != 0) end++
                s.name = String(strtab, idx, end - idx, Charsets.UTF_8)
            }
        }
    }

    private fun readPh64(phoff: Long, entsize: Int, count: Int): List<ProgramSegment> =
        (0 until count).map { i ->
            val c = Cursor(bytes, 0, bytes.size, (phoff + i.toLong() * entsize).toIntExact(), littleEndian)
            val type = c.u32(); val flags = c.u32()
            val offset = c.u64(); val vaddr = c.u64(); val paddr = c.u64()
            val filesz = c.u64(); val memsz = c.u64(); val align = c.u64()
            ProgramSegment(type.toLong() and 0xffffffffL, offset, vaddr, paddr, filesz, memsz, flags.toLong() and 0xffffffffL, align)
        }

    private fun readPh32(phoff: Long, entsize: Int, count: Int): List<ProgramSegment> =
        (0 until count).map { i ->
            val c = Cursor(bytes, 0, bytes.size, (phoff + i.toLong() * entsize).toIntExact(), littleEndian)
            val type = c.u32(); val offset = c.u32(); val vaddr = c.u32(); val paddr = c.u32()
            val filesz = c.u32(); val memsz = c.u32(); val flags = c.u32(); val align = c.u32()
            ProgramSegment(type.toLong() and 0xffffffffL, offset.toLong() and 0xffffffffL,
                vaddr.toLong() and 0xffffffffL, paddr.toLong() and 0xffffffffL,
                filesz.toLong() and 0xffffffffL, memsz.toLong() and 0xffffffffL,
                flags.toLong() and 0xffffffffL, align.toLong() and 0xffffffffL)
        }

    /** Lowest vaddr of a PT_LOAD segment — the canonical default load base. */
    fun defaultLoadBase(): Long = segments.filter { it.type.toInt() == PT_LOAD }.minOfOrNull { it.vaddr } ?: 0L

    companion object {
        const val SHT_NOBITS = 8
        const val PT_LOAD = 1
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("offset too large: $this")
    return toInt()
}
