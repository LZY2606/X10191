package compass.elf

import compass.dwarf.ParseException
import compass.dwarf.SectionInfo
import compass.sha256Hex

object Elf {
    data class ElfInfo(
        val is64: Boolean,
        val machine: Int,
        val sections: List<SectionInfo>,
        val warnings: List<String>,
    )

    fun parse(bytes: ByteArray): ElfInfo {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ParseException("not an ELF file")
        val is64 = bytes[4].toInt() == 2
        val littleEndian = bytes[5].toInt() == 1
        if (!littleEndian) throw ParseException("big-endian ELF not supported")
        val warnings = ArrayList<String>()

        fun u16(off: Int): Int {
            if (off + 2 > bytes.size) throw ParseException("ELF header truncated")
            return (bytes[off].toInt() and 0xFF) or ((bytes[off + 1].toInt() and 0xFF) shl 8)
        }
        fun u32(off: Int): Long {
            if (off + 4 > bytes.size) throw ParseException("ELF header truncated")
            var v = 0L
            for (i in 0..3) v = v or ((bytes[off + i].toLong() and 0xFF) shl (8 * i))
            return v
        }
        fun u64(off: Int): Long {
            if (off + 8 > bytes.size) throw ParseException("ELF header truncated")
            var v = 0L
            for (i in 0..7) v = v or ((bytes[off + i].toLong() and 0xFF) shl (8 * i))
            return v
        }

        val machine = u16(18)
        val shoff: Long
        val shentsize: Int
        var shnum: Int
        var shstrndx: Int
        if (is64) {
            shoff = u64(40); shentsize = u16(58); shnum = u16(60); shstrndx = u16(62)
        } else {
            shoff = u32(32); shentsize = u16(46); shnum = u16(48); shstrndx = u16(50)
        }
        if (shoff == 0L) return ElfInfo(is64, machine, emptyList(), listOf("no section table"))
        if (shentsize <= 0 || shoff + shentsize.toLong() * maxOf(shnum, 1) > bytes.size)
            throw ParseException("section header table out of bounds")

        data class Sh(val nameOff: Long, val type: Long, val offset: Long, val size: Long)
        fun shdr(i: Int): Sh {
            val o = (shoff + i.toLong() * shentsize).toInt()
            return if (is64) Sh(u32(o), u32(o + 4), u64(o + 24), u64(o + 32))
            else Sh(u32(o), u32(o + 4), u32(o + 16), u32(o + 20))
        }
        // Extended numbering: real counts live in section 0.
        if (shnum == 0) shnum = shdr(0).size.toInt()
        if (shstrndx == 0xFFFF) shstrndx = shdr(0).offset.toInt() // SHN_XINDEX via sh_link? kept simple
        val shstr = shdr(shstrndx)
        fun nameAt(off: Long): String {
            var p = (shstr.offset + off).toInt()
            if (p < 0 || p >= bytes.size) return "?"
            val sb = StringBuilder()
            while (p < bytes.size && bytes[p].toInt() != 0) { sb.append(bytes[p].toInt().toChar()); p++ }
            return sb.toString()
        }

        val sections = ArrayList<SectionInfo>()
        for (i in 0 until shnum) {
            val s = shdr(i)
            if (s.type == 8L /* SHT_NOBITS */ || s.size == 0L) continue
            val name = nameAt(s.nameOff)
            val end = s.offset + s.size
            val data: ByteArray = when {
                s.offset < 0 || s.offset >= bytes.size -> {
                    warnings.add("section $name offset outside file; zero-filled")
                    ByteArray(s.size.coerceAtMost(1 shl 20).toInt())
                }
                end > bytes.size -> {
                    warnings.add("section $name truncated by file end; clamped")
                    bytes.copyOfRange(s.offset.toInt(), bytes.size)
                }
                else -> bytes.copyOfRange(s.offset.toInt(), end.toInt())
            }
            sections.add(SectionInfo(name, s.offset, s.size, data.sha256Hex(), data))
        }
        return ElfInfo(is64, machine, sections, warnings)
    }
}
