package com.luopan.elf

import com.luopan.dwarf.Binary
import com.luopan.dwarf.DwarfReadException
import com.luopan.dwarf.Endian
import java.security.MessageDigest

object ElfParser {
    private const val SHT_NOBITS = 8

    fun parse(data: ByteArray): ElfImage {
        val diag = mutableListOf<String>()
        if (data.size < 16) throw DwarfReadException("file too small to be ELF")
        if (data[0] != 0x7f.toByte() || data[1] != 'E'.code.toByte() ||
            data[2] != 'L'.code.toByte() || data[3] != 'F'.code.toByte()
        ) throw DwarfReadException("bad ELF magic")
        val elfClass = data[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw DwarfReadException("unknown ELF class $elfClass")
        val endian = when (data[5].toInt() and 0xff) {
            1 -> Endian.LITTLE
            2 -> Endian.BIG
            else -> throw DwarfReadException("unknown ELF data encoding")
        }
        return if (elfClass == 2) parse64(data, endian, diag) else parse32(data, endian, diag)
    }

    private fun digest(data: ByteArray): ByteDigest {
        val h = MessageDigest.getInstance("SHA-256").digest(data)
        val hex = h.joinToString("") { "%02x".format(it) }
        val head = data.copyOfRange(0, minOf(16, data.size)).joinToString("") { "%02x".format(it) }
        return ByteDigest(hex, data.size.toLong(), head)
    }

    private class RawSec(
        val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long,
    )

    private fun parse64(data: ByteArray, endian: Endian, diag: MutableList<String>): ElfImage {
        val b = Binary(data, 0, data.size, endian)
        b.seek(16)
        val type = b.u2(); val machine = b.u2()
        b.u4(); val entry = b.u8()
        b.u8(); val shoff = b.u8()
        b.u4(); b.u2()
        val phentsize = b.u2(); val phnum = b.u2()
        val shentsize = b.u2(); val shnum0 = b.u2(); val shstrndx0 = b.u2()
        if (shoff == 0L) throw DwarfReadException("no section header table")
        if (shentsize < 64) throw DwarfReadException("bad ELF64 shentsize $shentsize")

        val raws = ArrayList<RawSec>()
        for (i in 0 until maxOf(1, shnum0)) {
            b.seek((shoff + i.toLong() * shentsize).toInt())
            raws.add(readRaw64(b))
        }
        val shnum = if (shnum0 == 0) raws[0].size.toInt() else shnum0
        while (raws.size < shnum) {
            val i = raws.size
            b.seek((shoff + i.toLong() * shentsize).toInt())
            raws.add(readRaw64(b))
        }
        val shstrndx = if (shstrndx0 == 0xffff) raws[0].link else shstrndx0

        val phdrs = readPhdr64(data, endian, phentsize, phnum)
        return buildImage(2, data, endian, type, machine, entry, raws, shnum, shstrndx, phdrs, diag)
    }

    private fun readRaw64(b: Binary): RawSec {
        val nameOff = b.u4(); val type = b.u4(); val flags = b.u8()
        val addr = b.u8(); val offset = b.u8(); val size = b.u8()
        val link = b.u4(); val info = b.u4()
        val addralign = b.u8(); val entsize = b.u8()
        return RawSec(nameOff, type, flags, addr, offset, size, link, info, addralign, entsize)
    }

    private fun readPhdr64(data: ByteArray, endian: Endian, phentsize: Int, phnum: Int): List<ElfProgramHeader> {
        if (phnum == 0 || phentsize < 56) return emptyList()
        val b = Binary(data, 0, data.size, endian)
        b.seek(32); val phoff = b.u8()
        val out = ArrayList<ElfProgramHeader>(phnum)
        for (i in 0 until phnum) {
            b.seek((phoff + i.toLong() * phentsize).toInt())
            val pt = b.u4(); val pf = b.u4()
            val off = b.u8(); val va = b.u8(); b.u8()
            val filesz = b.u8(); val memsz = b.u8(); val align = b.u8()
            out.add(ElfProgramHeader(pt, pf, off, va, filesz, memsz, align))
        }
        return out
    }

    private fun parse32(data: ByteArray, endian: Endian, diag: MutableList<String>): ElfImage {
        val b = Binary(data, 0, data.size, endian)
        b.seek(16)
        val type = b.u2(); val machine = b.u2()
        b.u4(); val entry = b.u4().toLong() and 0xffffffffL
        val phoff = b.u4().toLong() and 0xffffffffL
        val shoff = b.u4().toLong() and 0xffffffffL
        b.u4(); b.u2()
        val phentsize = b.u2(); val phnum = b.u2()
        val shentsize = b.u2(); val shnum0 = b.u2(); val shstrndx0 = b.u2()
        if (shoff == 0L) throw DwarfReadException("no section header table")
        if (shentsize < 40) throw DwarfReadException("bad ELF32 shentsize $shentsize")

        val raws = ArrayList<RawSec>()
        for (i in 0 until maxOf(1, shnum0)) {
            b.seek((shoff + i.toLong() * shentsize).toInt())
            raws.add(readRaw32(b))
        }
        val shnum = if (shnum0 == 0) raws[0].size.toInt() else shnum0
        while (raws.size < shnum) {
            val i = raws.size
            b.seek((shoff + i.toLong() * shentsize).toInt())
            raws.add(readRaw32(b))
        }
        val shstrndx = if (shstrndx0 == 0xffff) raws[0].link else shstrndx0

        val phdrs = readPhdr32(data, endian, phoff, phentsize, phnum)
        return buildImage(1, data, endian, type, machine, entry, raws, shnum, shstrndx, phdrs, diag)
    }

    private fun readRaw32(b: Binary): RawSec {
        val nameOff = b.u4(); val type = b.u4(); val flags = b.u4().toLong() and 0xffffffffL
        val addr = b.u4().toLong() and 0xffffffffL
        val offset = b.u4().toLong() and 0xffffffffL
        val size = b.u4().toLong() and 0xffffffffL
        val link = b.u4(); val info = b.u4()
        val addralign = b.u4().toLong() and 0xffffffffL
        val entsize = b.u4().toLong() and 0xffffffffL
        return RawSec(nameOff, type, flags, addr, offset, size, link, info, addralign, entsize)
    }

    private fun readPhdr32(
        data: ByteArray, endian: Endian, phoff: Long, phentsize: Int, phnum: Int,
    ): List<ElfProgramHeader> {
        if (phnum == 0 || phentsize < 32) return emptyList()
        val b = Binary(data, 0, data.size, endian)
        val out = ArrayList<ElfProgramHeader>(phnum)
        for (i in 0 until phnum) {
            b.seek((phoff + i.toLong() * phentsize).toInt())
            val pt = b.u4(); val off = b.u4().toLong() and 0xffffffffL
            val va = b.u4().toLong() and 0xffffffffL
            b.u4(); b.u4()
            val filesz = b.u4().toLong() and 0xffffffffL
            val memsz = b.u4().toLong() and 0xffffffffL
            val pf = b.u4(); val align = b.u4().toLong() and 0xffffffffL
            out.add(ElfProgramHeader(pt, pf, off, va, filesz, memsz, align))
        }
        return out
    }

    private fun buildImage(
        elfClass: Int, data: ByteArray, endian: Endian, type: Int, machine: Int, entry: Long,
        raws: List<RawSec>, shnum: Int, shstrndx: Int,
        phdrs: List<ElfProgramHeader>, diag: MutableList<String>,
    ): ElfImage {
        val nameTable = raws.getOrNull(shstrndx)?.let { rawBytes(data, it) }
            ?: throw DwarfReadException("missing section name string table")
        val sections = raws.mapIndexed { idx, r ->
            val nm = if (idx == 0) "" else safeCString(nameTable, r.nameOff)
            ElfSection(
                nm, r.type, r.flags, r.addr, r.offset, r.size, r.link, r.info,
                r.addralign, r.entsize, rawBytesOrEmpty(data, r, diag),
            )
        }
        val byName = sections.drop(1).filter { it.name.isNotEmpty() }.associateBy { it.name }
        val buildId = findBuildId(sections, endian)
        return ElfImage(
            elfClass, endian, machine, type, sections, phdrs, buildId, entry,
            type == ElfImage.ET_REL, diag, byName, digest(data),
        )
    }

    private fun findBuildId(sections: List<ElfSection>, endian: Endian): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        if (note.bytes.size < 12) return null
        val b = Binary(note.bytes, 0, note.bytes.size, endian)
        val namesz = b.u4(); val descsz = b.u4(); val kind = b.u4()
        if (kind != 3) return null
        val name = runCatching { b.readBytes(namesz) }.getOrNull() ?: return null
        if (name.toString(Charsets.US_ASCII).trimEnd('\u0000') != "GNU") return null
        val desc = runCatching { b.readBytes(descsz) }.getOrNull() ?: return null
        return desc.joinToString("") { "%02x".format(it) }
    }

    private fun rawBytes(data: ByteArray, r: RawSec): ByteArray {
        if (r.type == SHT_NOBITS) return ByteArray(0)
        val start = r.offset.toInt(); val len = r.size.toInt()
        if (start < 0 || len < 0 || start + len > data.size)
            throw DwarfReadException("section bytes out of file: off=$start size=$len")
        return data.copyOfRange(start, start + len)
    }

    private fun rawBytesOrEmpty(
        data: ByteArray, r: RawSec, diag: MutableList<String>,
    ): ByteArray = runCatching { rawBytes(data, r) }.getOrElse {
        diag.add("section(offset=${r.offset},size=${r.size}) bytes unreadable: ${it.message}")
        ByteArray(0)
    }

    private fun safeCString(table: ByteArray, off: Int): String {
        if (off < 0 || off >= table.size) return "<bad:$off>"
        var end = off
        while (end < table.size && table[end] != 0.toByte()) end++
        return String(table, off, end - off, Charsets.UTF_8)
    }
}
