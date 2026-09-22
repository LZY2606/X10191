package compass.elf

import java.nio.ByteBuffer
import java.nio.ByteOrder

class ElfException(msg: String) : Exception(msg)

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Long,
    val bytes: ByteArray,
)

data class ElfProgramHeader(
    val type: Long,
    val vaddr: Long,
    val offset: Long,
    val filesz: Long,
    val memsz: Long,
)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val elfType: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val programHeaders: List<ElfProgramHeader>,
) {
    /** Preferred load bias: lowest PT_LOAD vaddr (what runtime base is relative to). */
    val preferredBase: Long
        get() = programHeaders.filter { it.type == PT_LOAD }.minOfOrNull { it.vaddr } ?: 0L

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    companion object {
        const val PT_LOAD = 1L
        const val ET_DYN = 3
    }
}

object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16) throw ElfException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfException("not an ELF file")
        val is64 = when (bytes[4]) {
            1.toByte() -> false
            2.toByte() -> true
            else -> throw ElfException("bad ELF class ${bytes[4]}")
        }
        val le = when (bytes[5]) {
            1.toByte() -> true
            2.toByte() -> false
            else -> throw ElfException("bad ELF endianness ${bytes[5]}")
        }
        val buf = ByteBuffer.wrap(bytes).order(if (le) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        val elfType = buf.getShort(16).toInt() and 0xffff
        val entry: Long
        val phoff: Long
        val shoff: Long
        val phentsize: Int
        val phnum: Int
        val shentsize: Int
        val shnumRaw: Int
        val shstrndxRaw: Int
        if (is64) {
            entry = buf.getLong(24)
            phoff = buf.getLong(32)
            shoff = buf.getLong(40)
            phentsize = buf.getShort(54).toInt() and 0xffff
            phnum = buf.getShort(56).toInt() and 0xffff
            shentsize = buf.getShort(58).toInt() and 0xffff
            shnumRaw = buf.getShort(60).toInt() and 0xffff
            shstrndxRaw = buf.getShort(62).toInt() and 0xffff
        } else {
            entry = buf.getInt(24).toLong() and 0xffffffffL
            phoff = buf.getInt(28).toLong() and 0xffffffffL
            shoff = buf.getInt(32).toLong() and 0xffffffffL
            phentsize = buf.getShort(42).toInt() and 0xffff
            phnum = buf.getShort(44).toInt() and 0xffff
            shentsize = buf.getShort(46).toInt() and 0xffff
            shnumRaw = buf.getShort(48).toInt() and 0xffff
            shstrndxRaw = buf.getShort(50).toInt() and 0xffff
        }

        fun readShdr(i: Int): LongArray {
            val off = shoff + i.toLong() * shentsize
            if (off < 0 || off + shentsize > bytes.size) throw ElfException("section header $i out of bounds")
            return if (is64) longArrayOf(
                u32(buf, off.toInt()), u32(buf, off.toInt() + 4), u64(buf, off.toInt() + 8),
                u64(buf, off.toInt() + 16), u64(buf, off.toInt() + 24), u64(buf, off.toInt() + 32),
                u32(buf, off.toInt() + 40), u32(buf, off.toInt() + 44), u64(buf, off.toInt() + 48),
                u64(buf, off.toInt() + 56),
            ) else longArrayOf(
                u32(buf, off.toInt()), u32(buf, off.toInt() + 4), u32(buf, off.toInt() + 8),
                u32(buf, off.toInt() + 12), u32(buf, off.toInt() + 16), u32(buf, off.toInt() + 20),
                u32(buf, off.toInt() + 24), u32(buf, off.toInt() + 28), u32(buf, off.toInt() + 32),
                u32(buf, off.toInt() + 36),
            )
        }

        var shnum = shnumRaw
        var shstrndx = shstrndxRaw
        if (shoff != 0L && shnumRaw == 0) {
            val sh0 = readShdr(0)
            shnum = sh0[5].toInt() // sh_size holds real count
            if (shstrndxRaw == 0xffff) shstrndx = sh0[6].toInt() // sh_link holds real index
        }

        val phdrs = mutableListOf<ElfProgramHeader>()
        if (phoff != 0L) {
            for (i in 0 until phnum) {
                val off = phoff + i.toLong() * phentsize
                if (off + phentsize > bytes.size) throw ElfException("program header $i out of bounds")
                val o = off.toInt()
                if (is64) {
                    phdrs += ElfProgramHeader(u32(buf, o), u64(buf, o + 16), u64(buf, o + 8), u64(buf, o + 32), u64(buf, o + 40))
                } else {
                    phdrs += ElfProgramHeader(u32(buf, o), u32(buf, o + 4), u32(buf, o + 8), u32(buf, o + 16), u32(buf, o + 20))
                }
            }
        }

        val rawShdrs = (0 until shnum).map { readShdr(it) }
        val shstrOff = if (shstrndx in rawShdrs.indices) rawShdrs[shstrndx][4] else 0L
        val shstrSize = if (shstrndx in rawShdrs.indices) rawShdrs[shstrndx][5] else 0L

        fun shName(nameOff: Long): String {
            val start = shstrOff + nameOff
            if (start < 0 || start >= bytes.size || start >= shstrOff + shstrSize) return ""
            var end = start.toInt()
            val limit = minOf(bytes.size, (shstrOff + shstrSize).toInt())
            while (end < limit && bytes[end] != 0.toByte()) end++
            return String(bytes, start.toInt(), end - start.toInt(), Charsets.UTF_8)
        }

        val sections = rawShdrs.mapIndexed { i, sh ->
            val type = sh[1]
            val off = sh[4]
            val size = sh[5]
            val secBytes = if (type == 8L /* SHT_NOBITS */ || size == 0L) ByteArray(0) else {
                if (off < 0 || off + size > bytes.size) throw ElfException("section $i data out of bounds")
                bytes.copyOfRange(off.toInt(), (off + size).toInt())
            }
            ElfSection(i, shName(sh[0]), type, sh[2], sh[3], off, size, sh[6], secBytes)
        }
        return ElfFile(is64, le, elfType, entry, sections, phdrs)
    }

    private fun u32(b: ByteBuffer, off: Int) = b.getInt(off).toLong() and 0xffffffffL
    private fun u64(b: ByteBuffer, off: Int) = b.getLong(off)
}
