package com.linecompass.elf

import com.linecompass.io.ByteReader
import com.linecompass.io.ParseException

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Int,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val bytes: ByteArray?
) {
    val endAddr: Long get() = addr + size
    fun containsVaddr(vaddr: Long): Boolean = size > 0 && java.lang.Long.compareUnsigned(vaddr, addr) >= 0 &&
        java.lang.Long.compareUnsigned(vaddr, endAddr) < 0
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long
) {
    val endVaddr: Long get() = vaddr + memsz
    fun containsVaddr(vaddr: Long): Boolean =
        java.lang.Long.compareUnsigned(vaddr, vaddr) >= 0 &&
            java.lang.Long.compareUnsigned(vaddr, endVaddr) < 0
}

data class ElfFile(
    val elfClass: Int, // 1 = ELF32, 2 = ELF64
    val littleEndian: Boolean,
    val machine: Int,
    val type: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val sectionHeaderStringTable: ByteArray
) {
    private val byName = sections.groupingBy { it.name }.eachCount()

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    fun sectionBytes(name: String): ByteArray? = section(name)?.bytes

    /**
     * First PT_LOAD segment (sorted by vaddr) gives the base for load-bias
     * accounting against runtime module snapshots.
     */
    fun firstLoadVaddr(): Long? = segments.filter { it.type == PT_LOAD }
        .minByOrNull { it.vaddr }?.vaddr

    companion object {
        const val PT_LOAD = 1
        const val SHT_NOBITS = 8
    }
}

object ElfReader {
    fun parse(fileBytes: ByteArray): ElfFile {
        if (fileBytes.size < 64 || fileBytes[0] != 0x7f.toByte() ||
            fileBytes[1] != 'E'.code.toByte() || fileBytes[2] != 'L'.code.toByte() ||
            fileBytes[3] != 'F'.code.toByte()
        ) {
            throw ParseException("not an ELF file (bad magic)")
        }
        val elfClass = fileBytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ParseException("unknown EI_CLASS=$elfClass")
        val dataEncoding = fileBytes[5].toInt()
        val littleEndian = when (dataEncoding) {
            1 -> true
            2 -> false
            else -> throw ParseException("unknown EI_DATA=$dataEncoding")
        }
        val r = ByteReader(fileBytes, littleEndian, "elf", 16)
        r.u1(); r.u1() // EI_VERSION, EI_OSABI
        r.skip(8)

        return if (elfClass == 2) parse64(r, fileBytes, littleEndian) else parse32(r, fileBytes, littleEndian)
    }

    private fun parse64(r: ByteReader, b: ByteArray, le: Boolean): ElfFile {
        val type = r.u2()
        val machine = r.u2()
        r.u4() // version
        val entry = r.u8()
        val phoff = r.u8()
        val shoff = r.u8()
        r.u4() // flags
        val ehsize = r.u2()
        val phentsize = r.u2()
        val phnum = r.u2()
        val shentsize = r.u2()
        val shnum = r.u2()
        val shstrndx = r.u2()

        val segments = (0 until phnum).map { i ->
            r.seek((phoff + i.toLong() * phentsize).toInt())
            ElfSegment(
                type = r.u2(), flags = r.u2(),
                offset = r.u8(), vaddr = r.u8(), paddr = r.u8(),
                filesz = r.u8(), memsz = r.u8(), align = r.u8()
            )
        }

        val rawSections = (0 until shnum).map { i ->
            r.seek((shoff + i.toLong() * shentsize).toInt())
            RawSection(
                nameIdx = r.u4(), type = r.u2(), flags = r.u8(), addr = r.u8(),
                offset = r.u8(), size = r.u8(), link = r.u4(), info = r.u4(),
                addralign = r.u8(), entsize = r.u8()
            )
        }
        val shstr = extractStringTable(b, rawSections, shstrndx, le)
        val sections = rawSections.mapIndexed { index, rs ->
            val name = readName(shstr, rs.nameIdx)
            val bytes = when {
                rs.type == ElfFile.SHT_NOBITS || rs.size == 0L -> null
                else -> {
                    val start = rs.offset.toInt()
                    if (start.toLong() + rs.size > b.size) {
                        throw ParseException("section '$name' ($index) bytes exceed file size")
                    }
                    b.copyOfRange(start, (rs.offset + rs.size).toInt())
                }
            }
            ElfSection(name, rs.type, rs.flags, rs.addr, rs.offset.toInt(), rs.size,
                rs.link, rs.info, rs.addralign, bytes)
        }
        return ElfFile(2, le, machine, type, entry, sections, segments, shstr)
    }

    private fun parse32(r: ByteReader, b: ByteArray, le: Boolean): ElfFile {
        val type = r.u2()
        val machine = r.u2()
        r.u4()
        val entry = r.u4()
        val phoff = r.u4()
        val shoff = r.u4()
        r.u4() // flags
        r.u2() // ehsize
        val phentsize = r.u2()
        val phnum = r.u2()
        val shentsize = r.u2()
        val shnum = r.u2()
        val shstrndx = r.u2()

        val segs = (0 until phnum).map { i ->
            r.seek((phoff + i.toLong() * phentsize).toInt())
            ElfSegment(
                type = r.u2(),
                offset = r.u4(), vaddr = r.u4(), paddr = r.u4(),
                filesz = r.u4(), memsz = r.u4(), flags = r.u2(), align = r.u4()
            )
        }

        val rawSections = (0 until shnum).map { i ->
            r.seek((shoff + i.toLong() * shentsize).toInt())
            RawSection(
                nameIdx = r.u4(), type = r.u2(), flags = r.u4(), addr = r.u4(),
                offset = r.u4(), size = r.u4(), link = r.u4(), info = r.u4(),
                addralign = r.u4(), entsize = r.u4()
            )
        }
        val shstr = extractStringTable(b, rawSections, shstrndx, le)
        val sections = rawSections.map { rs ->
            val name = readName(shstr, rs.nameIdx)
            val bytes = if (rs.type == ElfFile.SHT_NOBITS || rs.size == 0L) null
            else b.copyOfRange(rs.offset.toInt(), (rs.offset + rs.size).toInt())
            ElfSection(name, rs.type, rs.flags, rs.addr, rs.offset.toInt(), rs.size,
                rs.link, rs.info, rs.addralign, bytes)
        }
        return ElfFile(1, le, machine, type, entry, sections, segs, shstr)
    }

    private data class RawSection(
        val nameIdx: Long, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long
    )

    private fun extractStringTable(b: ByteArray, raw: List<RawSection>, idx: Int, le: Boolean): ByteArray {
        if (idx < 0 || idx >= raw.size) return ByteArray(0)
        val rs = raw[idx]
        if (rs.offset + rs.size > b.size) throw ParseException("shstrtab exceeds file size")
        return b.copyOfRange(rs.offset.toInt(), (rs.offset + rs.size).toInt())
    }

    private fun readName(table: ByteArray, off: Long): String {
        val start = off.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
        if (start < 0 || start >= table.size) return ""
        var end = start
        while (end < table.size && table[end].toInt() != 0) end++
        return String(table, start, end - start)
    }
}
