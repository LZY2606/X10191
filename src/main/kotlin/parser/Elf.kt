package parser

import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val addralign: Long,
) {
    val endAddr: Long get() = if (size == 0L) addr else addr + size
    fun reader(file: ByteArray): BinaryReader =
        BinaryReader(file, offset.toInt(), (offset + size).toInt())
}

data class ProgramHeader(val type: Long, val flags: Long, val offset: Long, val vaddr: Long, val paddr: Long,
                         val filesz: Long, val memsz: Long, val align: Long) {
    val isLoad: Boolean get() = type == 1L // PT_LOAD
    val endVaddr: Long get() = vaddr + memsz
}

data class ElfFile(
    val elfClass: Int,         // 1 = ELF32, 2 = ELF64
    val dataEncoding: Int,     // 1 little, 2 big
    val machine: Int,
    val sections: List<ElfSection>,
    val programHeaders: List<ProgramHeader>,
    val entry: Long,
    val raw: ByteArray,
    val sha256: String,
    val size: Long,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    fun reader(sec: ElfSection): BinaryReader = sec.reader(raw)
    fun sectionBytes(sec: ElfSection): ByteArray =
        raw.copyOfRange(sec.offset.toInt(), (sec.offset + sec.size).toInt())

    /** Smallest mapped virtual address. Load bias is runtimeBase - preferredBase. */
    fun preferredBase(): Long? = programHeaders.filter { it.isLoad }.minByOrNull { it.vaddr }?.vaddr

    /** File offset of a virtual address via PT_LOAD mapping. */
    fun fileOffsetForVaddr(vaddr: Long): Long? {
        val ph = programHeaders.firstOrNull { it.isLoad && vaddr >= it.vaddr && vaddr < it.vaddr + it.filesz }
            ?: return null
        return ph.offset + (vaddr - ph.vaddr)
    }
}

object ElfParser {
    fun parse(raw: ByteArray): ElfFile {
        if (raw.size < 16) throw ParseException("not an ELF file: too small")
        if (raw[0] != 0x7f.toByte() || raw[1] != 'E'.code.toByte() || raw[2] != 'L'.code.toByte() || raw[3] != 'F'.code.toByte())
            throw ParseException("not an ELF file: bad magic")
        val elfClass = raw[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ParseException("unsupported EI_CLASS=${raw[4]}")
        val encoding = raw[5].toInt()
        if (encoding != 1) throw ParseException("only little-endian ELF supported (EI_DATA=$encoding)")
        return if (elfClass == 2) parse64(raw, encoding) else parse32(raw, encoding)
    }

    private fun rd(raw: ByteArray, off: Int, size: Int): Long {
        var v = 0L
        for (i in 0 until size) v = v or ((raw[off + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    private fun parse64(raw: ByteArray, enc: Int): ElfFile {
        val machine = rd(raw, 18, 2).toInt()
        val entry = rd(raw, 24, 8)
        val phoff = rd(raw, 32, 8)
        val shoff = rd(raw, 40, 8)
        val phentsize = rd(raw, 54, 2).toInt()
        val phnum = rd(raw, 56, 2).toInt()
        val shentsize = rd(raw, 58, 2).toInt()
        val shnum = rd(raw, 60, 2).toInt()
        val shstrndx = rd(raw, 62, 2).toInt()

        val phs = (0 until phnum).map { i ->
            val o = (phoff + i * phentsize).toInt()
            ProgramHeader(
                type = rd(raw, o, 4),
                flags = rd(raw, o + 4, 8),
                offset = rd(raw, o + 8, 8),
                vaddr = rd(raw, o + 16, 8),
                paddr = rd(raw, o + 24, 8),
                filesz = rd(raw, o + 32, 8),
                memsz = rd(raw, o + 40, 8),
                align = rd(raw, o + 48, 8),
            )
        }

        data class RawSh(val nameOff: Int, val type: Long, val flags: Long, val addr: Long, val off: Long,
                         val size: Long, val link: Int, val info: Long, val align: Long)
        val rawSh = (0 until shnum).map { i ->
            val o = (shoff + i * shentsize).toInt()
            RawSh(
                nameOff = rd(raw, o, 4).toInt(),
                type = rd(raw, o + 4, 4),
                flags = rd(raw, o + 8, 8),
                addr = rd(raw, o + 16, 8),
                off = rd(raw, o + 24, 8),
                size = rd(raw, o + 32, 8),
                link = rd(raw, o + 40, 4).toInt(),
                info = rd(raw, o + 44, 8),
                align = rd(raw, o + 48, 8),
            )
        }
        val shstr = rawSh.getOrNull(shstrndx)
        val names = if (shstr != null) raw.copyOfRange(shstr.off.toInt(), (shstr.off + shstr.size).toInt()) else ByteArray(0)
        fun nm(off: Int): String {
            var p = off
            val b = StringBuilder()
            while (p < names.size && names[p].toInt() != 0) { b.append(names[p].toInt().toChar()); p++ }
            return b.toString()
        }
        val sections = rawSh.mapIndexed { idx, s ->
            ElfSection(if (idx == 0) "" else nm(s.nameOff), s.type, s.flags, s.addr, s.off, s.size, s.link, s.info, s.align)
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        return ElfFile(2, enc, machine, sections, phs, entry, raw, digest, raw.size.toLong())
    }

    private fun parse32(raw: ByteArray, enc: Int): ElfFile {
        val machine = rd(raw, 18, 2).toInt()
        val entry = rd(raw, 24, 4)
        val phoff = rd(raw, 32, 4)
        val shoff = rd(raw, 36, 4)
        val phentsize = rd(raw, 42, 2).toInt()
        val phnum = rd(raw, 44, 2).toInt()
        val shentsize = rd(raw, 46, 2).toInt()
        val shnum = rd(raw, 48, 2).toInt()
        val shstrndx = rd(raw, 50, 2).toInt()

        val phs = (0 until phnum).map { i ->
            val o = (phoff + i * phentsize).toInt()
            ProgramHeader(
                type = rd(raw, o, 4),
                flags = rd(raw, o + 24, 4),
                offset = rd(raw, o + 4, 4),
                vaddr = rd(raw, o + 8, 4),
                paddr = rd(raw, o + 12, 4),
                filesz = rd(raw, o + 16, 4),
                memsz = rd(raw, o + 20, 4),
                align = rd(raw, o + 28, 4),
            )
        }

        data class RawSh(val nameOff: Int, val type: Long, val flags: Long, val addr: Long, val off: Long,
                         val size: Long, val link: Int, val info: Long, val align: Long)
        val rawSh = (0 until shnum).map { i ->
            val o = (shoff + i * shentsize).toInt()
            RawSh(
                nameOff = rd(raw, o, 4).toInt(),
                type = rd(raw, o + 4, 4),
                flags = rd(raw, o + 8, 4),
                addr = rd(raw, o + 12, 4),
                off = rd(raw, o + 16, 4),
                size = rd(raw, o + 20, 4),
                link = rd(raw, o + 24, 4).toInt(),
                info = rd(raw, o + 28, 4),
                align = rd(raw, o + 32, 4),
            )
        }
        val shstr = rawSh.getOrNull(shstrndx)
        val names = if (shstr != null) raw.copyOfRange(shstr.off.toInt(), (shstr.off + shstr.size).toInt()) else ByteArray(0)
        fun nm(off: Int): String {
            var p = off
            val b = StringBuilder()
            while (p < names.size && names[p].toInt() != 0) { b.append(names[p].toInt().toChar()); p++ }
            return b.toString()
        }
        val sections = rawSh.mapIndexed { idx, s ->
            ElfSection(if (idx == 0) "" else nm(s.nameOff), s.type, s.flags, s.addr, s.off, s.size, s.link, s.info, s.align)
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        return ElfFile(1, enc, machine, sections, phs, entry, raw, digest, raw.size.toLong())
    }
}
