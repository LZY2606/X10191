package compass.elf

import compass.binary.ByteReader
import compass.binary.DwarfParseException
import java.nio.ByteOrder

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val address: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val entrySize: Long,
)

data class ProgramHeader(val type: Int, val flags: Int, val offset: Long, val vaddr: Long, val paddr: Long, val filesz: Long, val memsz: Long, val align: Long)

data class ElfFile(
    val elfClass: Int,
    val endian: ByteOrder,
    val machine: Int,
    val entry: Long,
    val type: Int,
    val sections: List<ElfSection>,
    val segments: List<ProgramHeader>,
    val raw: ByteArray,
    val buildId: String?,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(name: String): ByteArray? {
        val s = section(name) ?: return null
        if (s.offset < 0 || s.size < 0 || s.offset + s.size > raw.size) {
            throw DwarfParseException("section $name: offset/size [${s.offset},+${s.size}] outside file of ${raw.size} bytes")
        }
        return raw.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    /** Physical/segmented address: convert paddr to file offset via PT_LOAD segments. */
    fun physicalToOffset(paddr: Long): Long? =
        segments.firstOrNull { it.type == PT_LOAD && paddr in it.paddr until (it.paddr + it.memsz) }
            ?.let { seg -> paddr - seg.paddr + seg.offset }

    fun virtualToOffset(vaddr: Long): Long? {
        val s = sections.firstOrNull { s1 -> s1.address != 0L && s1.size != 0L && vaddr in s1.address until s1.address + s1.size }
        if (s != null) return vaddr - s.address + s.offset
        val seg = segments.firstOrNull { it.type == PT_LOAD && vaddr in it.vaddr until (it.vaddr + it.filesz) }
        return seg?.let { vaddr - it.vaddr + it.offset }
    }

    companion object {
        const val PT_LOAD = 1
        const val SHT_SYMTAB = 2
        const val SHT_STRTAB = 3
        const val SHT_NOBITS = 8
    }
}

object ElfParser {
    fun parse(data: ByteArray): ElfFile {
        if (data.size < 16 || data[0].toInt() != 0x7f || data[1].toInt() != 'E'.code || data[2].toInt() != 'L'.code || data[3].toInt() != 'F'.code) {
            throw DwarfParseException("not an ELF file (bad magic)")
        }
        val elfClass = data[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw DwarfParseException("unknown ELF class $elfClass")
        val endian = when (data[5].toInt()) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw DwarfParseException("unknown ELF data encoding ${data[5]}")
        }
        val r = ByteReader(data, "<elf>", 0, data.size, endian)
        r.seek(16)
        val type = r.u16()
        val machine = r.u16()
        r.u32() // e_version
        val entry: Long
        val phoff: Long
        val shoff: Long
        val phentsize: Int
        val phnum: Int
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        if (elfClass == 2) {
            entry = r.u64()
            phoff = r.u64()
            shoff = r.u64()
            r.u32()
            phentsize = r.u16(); phnum = r.u16()
            shentsize = r.u16(); shnum = r.u16(); shstrndx = r.u16()
        } else {
            entry = r.u32()
            phoff = r.u32()
            shoff = r.u32()
            r.u32()
            phentsize = r.u16(); phnum = r.u16()
            shentsize = r.u16(); shnum = r.u16(); shstrndx = r.u16()
        }
        if (shnum == 0 || shentsize == 0) throw DwarfParseException("ELF has no section headers (stripped/stripped-style)")

        val rawHeaders = ArrayList<List<Long>>(shnum)
        repeat(shnum) { i ->
            r.seek((shoff + i.toLong() * shentsize).toInt())
            val values = if (elfClass == 2) {
                val shType = r.u32()
                val shFlags = r.u64()
                val shAddr = r.u64()
                val shOffset = r.u64()
                val shSize = r.u64()
                val shLink = r.u32()
                val shInfo = r.u32()
                val shAddralign = r.u64()
                val shEntsize = r.u64()
                listOf(shType.toLong(), shFlags, shAddr, shOffset, shSize, shLink.toLong(), shInfo.toLong(), shAddralign, shEntsize)
            } else {
                val shName = r.u32()
                val shType = r.u32()
                val shFlags = r.u32()
                val shAddr = r.u32()
                val shOffset = r.u32()
                val shSize = r.u32()
                val shLink = r.u32()
                val shInfo = r.u32()
                val shAddralign = r.u32()
                val shEntsize = r.u32()
                listOf(shName.toLong(), shType.toLong(), shFlags, shAddr, shOffset, shSize, shLink.toLong(), shInfo.toLong(), shAddralign, shEntsize)
            }
            if (elfClass == 1) rawHeaders.add(values) else rawHeaders.add(values)
        }

        // section name string table
        val shstr = if (shstrndx >= shnum) null else rawHeaders[shstrndx]
        fun nameOf(index: Int): String {
            if (shstr == null || elfClass == 2) return ""
            val nameOff = rawHeaders[index][0].toInt()
            val strOff = shstr[3].toInt()
            return readStr(data, strOff + nameOff, endian)
        }

        val sections = ArrayList<ElfSection>(shnum)
        if (elfClass == 2) {
            // for 64-bit, name index must be read separately
            for (i in 0 until shnum) {
                r.seek((shoff + i.toLong() * shentsize).toInt())
                val nameIdx = r.u32()
                val v = rawHeaders[i]
                sections.add(
                    ElfSection(name64(data, shstr, nameIdx, endian), v[0].toInt(), v[1], v[2], v[3], v[4], v[5].toInt(), v[6].toInt(), v[8]),
                )
            }
        } else {
            for (i in 0 until shnum) {
                val v = rawHeaders[i]
                sections.add(
                    ElfSection(nameOf(i), v[1].toInt(), v[2], v[3], v[4], v[5], v[6].toInt(), v[7].toInt(), v[9]),
                )
            }
        }

        val segments = ArrayList<ProgramHeader>(phnum)
        repeat(phnum) { i ->
            r.seek((phoff + i.toLong() * phentsize).toInt())
            if (elfClass == 2) {
                val pType = r.u32()
                val pFlags = r.u32()
                val pOffset = r.u64()
                val pVaddr = r.u64()
                val pPaddr = r.u64()
                val pFilesz = r.u64()
                val pMemsz = r.u64()
                r.u64() // align
                segments.add(ProgramHeader(pType, pFlags, pOffset, pVaddr, pPaddr, pFilesz, pMemsz, 0))
            } else {
                val pType = r.u32()
                val pOffset = r.u32()
                val pVaddr = r.u32()
                val pPaddr = r.u32()
                val pFilesz = r.u32()
                val pMemsz = r.u32()
                val pFlags = r.u32()
                r.u32()
                segments.add(ProgramHeader(pType, pFlags, pOffset.toLong(), pVaddr.toLong(), pPaddr.toLong(), pFilesz.toLong(), pMemsz.toLong(), 0))
            }
        }

        val buildId = findBuildId(data, elfClass, endian, sections)
        return ElfFile(elfClass, endian, machine, entry, type, sections, segments, data, buildId)
    }

    private fun readStr(data: ByteArray, off: Int, @Suppress("UNUSED_PARAMETER") endian: java.nio.ByteOrder): String {
        var p = off
        while (p < data.size && data[p].toInt() != 0) p++
        if (off > data.size) return ""
        return String(data, off, (p - off).coerceAtLeast(0), Charsets.UTF_8)
    }

    private fun name64(data: ByteArray, shstr: List<Long>?, nameIdx: Int, endian: java.nio.ByteOrder): String {
        if (shstr == null) return ""
        return readStr(data, shstr[3].toInt() + nameIdx, endian)
    }

    private fun findBuildId(data: ByteArray, elfClass: Int, endian: java.nio.ByteOrder, sections: List<ElfSection>): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        if (note.offset + note.size > data.size) return null
        val r = ByteReader(data, ".note.gnu.build-id", note.offset.toInt(), (note.offset + note.size).toInt(), endian)
        try {
            while (r.remaining > 12) {
                val namesz = if (elfClass == 2) r.u32().toInt() else r.u32().toInt()
                val descsz = r.u32().toInt()
                r.u32() // type
                if (namesz < 0 || descsz < 0 || namesz + descsz > r.remaining + 8) return null
                val nameStart = r.pos
                r.skip((namesz + 3) and 3.inv())
                val descStart = r.pos
                r.seek(descStart)
                val desc = r.readBytes(descsz)
                val name = String(data, nameStart, namesz - 1, Charsets.UTF_8)
                if (name == "GNU" && (descsz == 16 || descsz == 20)) {
                    return desc.joinToString("") { "%02x".format(it) }
                }
            }
        } catch (_: DwarfParseException) {
            return null
        }
        return null
    }
}
