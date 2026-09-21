package compass.elf

import compass.BinException
import compass.BinReader
import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Int,
    val size: Int,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val sectionBytes: ByteArray?
) {
    fun containsFileOffset(off: Int): Boolean = off in offset until offset + size
}

/** NT_GNU_BUILD_ID = 3 */
data class ElfProgramHeader(val type: Int, val offset: Int, val vaddr: Long, val filesz: Long, val memsz: Long, val flags: Int)

class ElfFile(
    val fileName: String,
    val fileClass: Int,       // 1=ELF32, 2=ELF64
    val dataEncoding: Int,    // 1=LE, 2=BE
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val programHeaders: List<ElfProgramHeader>,
    val buildId: String?,
    val sha256: String,
    val byteLength: Int,
    val rawBytes: ByteArray
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(name: String): ByteArray? = section(name)?.let { s ->
        if (s.size == 0) ByteArray(0)
        else s.sectionBytes ?: throw BinException("section ${s.name} 内容超出文件范围")
    }

    fun sectionMap(): List<Map<String, Any?>> = sections
        .filter { it.type != 0 /* SHT_NULL */ }
        .map {
            mapOf(
                "name" to it.name,
                "type" to shtName(it.type),
                "addr" to "0x${it.addr.toString(16)}",
                "offset" to it.offset,
                "size" to it.size,
                "flags" to shFlags(it.flags),
                "present" to (it.sectionBytes != null || it.size == 0)
            )
        }

    companion object {
        const val SHT_PROGBITS = 1
        const val SHT_STRTAB = 3
        const val SHT_NOBITS = 8

        fun shtName(t: Int): String = when (t) {
            0 -> "NULL"; 1 -> "PROGBITS"; 2 -> "SYMTAB"; 3 -> "STRTAB"; 7 -> "NOTE"
            8 -> "NOBITS"; 9 -> "REL"; 11 -> "DYNSYM"; 0x6ffffff6 -> "GNU_HASH"
            0x6fffffff -> "LORESERVE? VERNEED"; else -> "0x${t.toString(16)}"
        }

        fun shFlags(f: Long): String {
            val sb = StringBuilder()
            if (f and 0x2L != 0L) sb.append('A')
            if (f and 0x1L != 0L) sb.append('W')
            if (f and 0x4L != 0L) sb.append('X')
            return sb.toString()
        }
    }
}

object ElfParser {
    fun parse(bytes: ByteArray, fileName: String): ElfFile {
        if (bytes.size < 64) throw BinException("文件过小，不是合法 ELF")
        if (!(bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() && bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte()))
            throw BinException("缺少 ELF 魔数")
        val r = BinReader(bytes)
        val elfClass = r.u1()
        if (elfClass != 1 && elfClass != 2) throw BinException("未知 EI_CLASS=${elfClass}")
        val encoding = r.u1()
        if (encoding != 1) throw BinException("仅支持小端 ELF（EI_DATA=$encoding）")
        r.seek(0x12)
        val machine = r.u2()
        if (elfClass == 2) {
            r.seek(0x18); val entry = r.u8()
            r.seek(0x20); val phoff = r.u8()
            r.seek(0x28); val shoff = r.u8()
            r.seek(0x36); val phentsize = r.u2()
            r.seek(0x38); val phnum = r.u2()
            r.seek(0x3a); val shentsize = r.u2()
            r.seek(0x3c); val shnum = r.u2()
            r.seek(0x3e); val shstrndx = r.u2()
            require(shoff in 0..Int.MAX_VALUE.toLong()) { "e_shoff 异常" }
            require(phoff in 0..Int.MAX_VALUE.toLong()) { "e_phoff 异常" }
            if (shnum > 4096 || phnum > 4096) throw BinException("section/program header 数量异常")
            if (shentsize != 64 && shentsize != 0) throw BinException("异常 e_shentsize=$shentsize")
            val sections = readSections64(bytes, shoff.toInt(), shnum, shentsize, shstrndx)
            val phdrs = readPhdrs64(bytes, phoff.toInt(), phnum, phentsize)
            val buildId = extractBuildId64(bytes, phdrs)
            return ElfFile(
                fileName, elfClass, encoding, machine, entry, sections, phdrs,
                buildId, sha256(bytes), bytes.size, bytes
            )
        } else {
            r.seek(0x18); val entry = r.u4().toLong() and 0xffffffffL
            r.seek(0x1c); val phoff = r.u4().toLong() and 0xffffffffL
            r.seek(0x20); val shoff = r.u4().toLong() and 0xffffffffL
            r.seek(0x2a); val phentsize = r.u2()
            r.seek(0x2c); val phnum = r.u2()
            r.seek(0x2e); val shentsize = r.u2()
            r.seek(0x30); val shnum = r.u2()
            r.seek(0x32); val shstrndx = r.u2()
            if (shnum > 4096 || phnum > 4096) throw BinException("section/program header 数量异常")
            if (shentsize != 40 && shentsize != 0) throw BinException("异常 e_shentsize=$shentsize")
            val sections = readSections32(bytes, shoff.toInt(), shnum, shentsize, shstrndx)
            val phdrs = readPhdrs32(bytes, phoff.toInt(), phnum, phentsize)
            val buildId = extractBuildId32(bytes, phdrs)
            return ElfFile(
                fileName, elfClass, encoding, machine, entry, sections, phdrs,
                buildId, sha256(bytes), bytes.size, bytes
            )
        }
    }

    private class RawSh(val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
                        val offset: Long, val size: Long, val link: Int, val info: Int, val align: Long)

    private fun readSections64(bytes: ByteArray, shoff: Int, shnum: Int, shentsize: Int, shstrndx: Int): List<ElfSection> {
        if (shnum == 0 || shoff == 0) return emptyList()
        val raws = ArrayList<RawSh>(shnum)
        for (i in 0 until shnum) {
            val r = BinReader(bytes, shoff + i * shentsize)
            val nameOff = r.u4(); val type = r.u2(); val flags = r.u8(); val addr = r.u8()
            val off = r.u8(); val size = r.u8(); val link = r.u4(); val info = r.u4()
            r.pos += 8 // align + entsize
            raws.add(RawSh(nameOff, type, flags, addr, off, size, link, info, 0))
        }
        return buildSections(bytes, raws, shstrndx)
    }

    private fun readSections32(bytes: ByteArray, shoff: Int, shnum: Int, shentsize: Int, shstrndx: Int): List<ElfSection> {
        if (shnum == 0 || shoff == 0) return emptyList()
        val raws = ArrayList<RawSh>(shnum)
        for (i in 0 until shnum) {
            val r = BinReader(bytes, shoff + i * shentsize)
            val nameOff = r.u4(); val type = r.u4(); val flags = r.u4().toLong() and 0xffffffffL
            val addr = r.u4().toLong() and 0xffffffffL; val off = r.u4().toLong() and 0xffffffffL
            val size = r.u4().toLong() and 0xffffffffL; val link = r.u4(); val info = r.u4()
            raws.add(RawSh(nameOff, type, flags, addr, off, size, link, info, 0))
        }
        return buildSections(bytes, raws, shstrndx)
    }

    private fun buildSections(bytes: ByteArray, raws: List<RawSh>, shstrndx: Int): List<ElfSection> {
        if (shstrndx >= raws.size) throw BinException("e_shstrndx 越界")
        val strtab = raws[shstrndx]
        if (strtab.offset > Int.MAX_VALUE || strtab.size > Int.MAX_VALUE) throw BinException("shstrtab 过大")
        fun nameAt(off: Int): String {
            val base = strtab.offset.toInt() + off
            if (base < 0 || base >= bytes.size) throw BinException("section 名偏移越界")
            val end = run {
                var e = base
                while (e < bytes.size && bytes[e].toInt() != 0) e++
                e
            }
            return String(bytes, base, end - base, Charsets.UTF_8)
        }
        return raws.mapIndexed { idx, rs ->
            if (rs.offset > Int.MAX_VALUE || rs.size > Int.MAX_VALUE)
                throw BinException("section[$idx] offset/size 超出 32 位文件范围")
            val name = runCatching { nameAt(rs.nameOff) }.getOrDefault("<invalid-name:$idx>")
            val off = rs.offset.toInt(); val sz = rs.size.toInt()
            val content = when (rs.type) {
                ElfFile.SHT_NOBITS -> ByteArray(0)
                else -> if (sz == 0) ByteArray(0)
                else if (off >= 0 && off + sz <= bytes.size) bytes.copyOfRange(off, off + sz)
                else null // 声明超出文件：隔离，但 section 仍出现在地图里
            }
            ElfSection(name, rs.type, rs.flags, rs.addr, off, sz, rs.link, rs.info, rs.align, content)
        }
    }

    private fun readPhdrs64(bytes: ByteArray, phoff: Int, phnum: Int, phentsize: Int): List<ElfProgramHeader> {
        if (phnum == 0 || phoff == 0) return emptyList()
        val out = ArrayList<ElfProgramHeader>(phnum)
        for (i in 0 until phnum) {
            val r = BinReader(bytes, phoff + i * phentsize)
            val type = r.u4(); val flags = r.u4(); val off = r.u8(); val va = r.u8()
            r.pos += 8 // paddr
            val filesz = r.u8(); val memsz = r.u8()
            out.add(ElfProgramHeader(type, off.toIntSafe(), va, filesz, memsz, flags))
        }
        return out
    }

    private fun readPhdrs32(bytes: ByteArray, phoff: Int, phnum: Int, phentsize: Int): List<ElfProgramHeader> {
        if (phnum == 0 || phoff == 0) return emptyList()
        val out = ArrayList<ElfProgramHeader>(phnum)
        for (i in 0 until phnum) {
            val r = BinReader(bytes, phoff + i * phentsize)
            val type = r.u4(); val off = r.u4().toLong() and 0xffffffffL; val va = r.u4().toLong() and 0xffffffffL
            r.pos += 4; val filesz = r.u4().toLong() and 0xffffffffL; val memsz = r.u4().toLong() and 0xffffffffL
            val flags = r.u4()
            out.add(ElfProgramHeader(type, off.toIntSafe(), va, filesz, memsz, flags))
        }
        return out
    }

    private fun Long.toIntSafe(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw BinException("program header offset 异常")
        return toInt()
    }

    private fun extractBuildId64(bytes: ByteArray, phdrs: List<ElfProgramHeader>): String? {
        val note = phdrs.firstOrNull { it.type == 4 /* PT_NOTE */ } ?: return null
        return runCatching { readBuildId(bytes, note.offset) }.getOrNull()
    }

    private fun extractBuildId32(bytes: ByteArray, phdrs: List<ElfProgramHeader>): String? {
        val note = phdrs.firstOrNull { it.type == 4 } ?: return null
        return runCatching { readBuildId(bytes, note.offset) }.getOrNull()
    }

    private fun readBuildId(bytes: ByteArray, off: Int): String? {
        var pos = off
        while (pos + 12 <= bytes.size) {
            val r = BinReader(bytes, pos)
            val namesz = r.u4(); val descsz = r.u4(); val ntype = r.u4()
            if (namesz > 64 || descsz > 64) return null
            pos = r.pos
            pos += (namesz + 3) and 3.inv()
            if (pos + descsz > bytes.size) return null
            if (ntype == 3 /* NT_GNU_BUILD_ID */) {
                val desc = bytes.copyOfRange(pos, pos + descsz)
                return desc.joinToString("") { "%02x".format(it) }
            }
            pos += (descsz + 3) and 3.inv()
            if (descsz == 0 && namesz == 0) return null
        }
        return null
    }

    private fun sha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
