package compass.elf

import compass.dwarf.Cursor
import compass.dwarf.CursorError
import java.security.MessageDigest

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray,
) {
    val sha256: String get() = sha256Of(data)
}

data class ElfSegment(val type: Long, val vaddr: Long, val memSize: Long, val fileSize: Long)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val sha256: String,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    /** PT_LOAD 的最小 vaddr，用于提示模块链接基址（不是运行时 load bias）。 */
    val linkBase: Long get() = segments.filter { it.type == 1L }.minOfOrNull { it.vaddr } ?: 0L

    companion object {
        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
                || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) throw CursorError("not an ELF file")
            val is64 = bytes[4].toInt() == 2
            val little = bytes[5].toInt() != 2
            val c = Cursor(bytes, littleEndian = little)
            c.seek(16)
            c.u16() // e_type
            val machine = c.u16()
            c.u32() // e_version
            if (is64) { c.u64(); c.u32(); c.u64() } else { c.u32(); c.u32(); c.u32() } // entry, phoff, shoff
            c.seek(if (is64) 24 else 20)
            val phoff = if (is64) c.u64() else c.u32()
            val shoff = if (is64) c.u64() else c.u32()
            c.u32() // flags
            c.u16() // ehsize
            val phentsize = c.u16(); val phnum = c.u16()
            val shentsize = c.u16(); val shnum = c.u16(); val shstrndx = c.u16()

            data class Shdr(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
            val shdrs = ArrayList<Shdr>()
            for (i in 0 until shnum) {
                val base = shoff + i.toLong() * shentsize
                if (base + shentsize > bytes.size) throw CursorError("section header $i out of bounds")
                c.seek(base.toInt())
                val nameOff = c.u32()
                val type = c.u32()
                if (is64) { c.u64(); val addr = c.u64(); val off = c.u64(); val size = c.u64(); shdrs.add(Shdr(nameOff, type, addr, off, size)) }
                else { c.u32(); val addr = c.u32(); val off = c.u32(); val size = c.u32(); shdrs.add(Shdr(nameOff, type, addr, off, size)) }
            }
            val strtab = if (shstrndx in shdrs.indices) shdrs[shstrndx] else null
            fun nameOf(off: Long): String {
                if (strtab == null) return ""
                val at = strtab.off + off
                if (at < 0 || at >= bytes.size) return ""
                var end = at.toInt()
                while (end < bytes.size && bytes[end] != 0.toByte()) end++
                return String(bytes, at.toInt(), end - at.toInt(), Charsets.UTF_8)
            }
            val sections = shdrs.mapIndexed { i, s ->
                val end = s.off + s.size
                val data = if (s.type == 8L || s.size == 0L || end > bytes.size) ByteArray(0)
                    else bytes.copyOfRange(s.off.toInt(), end.toInt())
                ElfSection(i, nameOf(s.nameOff), s.type, s.addr, s.off, s.size, data)
            }
            val segments = ArrayList<ElfSegment>()
            for (i in 0 until phnum) {
                val base = phoff + i.toLong() * phentsize
                if (base + phentsize > bytes.size) break
                c.seek(base.toInt())
                val type = c.u32()
                if (is64) { c.u32(); c.u64(); val vaddr = c.u64(); c.u64(); val filesz = c.u64(); val memsz = c.u64(); segments.add(ElfSegment(type.toLong(), vaddr, memsz, filesz)) }
                else { c.u32(); val vaddr = c.u32(); c.u32(); val filesz = c.u32(); val memsz = c.u32(); segments.add(ElfSegment(type.toLong(), vaddr, memsz, filesz)) }
            }
            return ElfFile(is64, little, machine, sections, segments, sha256Of(bytes))
        }

        fun sha256Of(data: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
    }
}
