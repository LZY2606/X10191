package compass.elf

import compass.binary.ByteReader
import compass.binary.ParseException

/** Parsed ELF file: identity, sections and raw bytes retained for re-resolution. */
class ElfFile(
    val elfClass: Int,
    val endianLittle: Boolean,
    val machine: Int,
    val type: Int,
    val sections: List<ElfSection>,
    val sectionByName: Map<String, ElfSection>,
    val bytes: ByteArray,
    val buildId: String?,
) {
    fun section(name: String): ElfSection? = sectionByName[name]

    /** Reader scoped to a section's bytes; throws on out-of-bounds windows. */
    fun sectionReader(section: ElfSection): ByteReader {
        if (section.offset.toLong() + section.size > bytes.size.toLong()) {
            throw ParseException("section ${section.name} file range out of bounds")
        }
        return ByteReader(bytes, section.offset, section.offset + section.size, section.offset)
    }

    val is64Bit get() = elfClass == 2
    val isDyn get() = type == 3
}

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val address: Long,
    val offset: Int,
    val size: Int,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val index: Int,
)

object Elf {
    fun parse(bytes: ByteArray): ElfFile {
        val r = ByteReader(bytes)
        if (r.remaining() < 16 || r.u1() != 0x7f || r.u1() != 'E'.code || r.u1() != 'L'.code || r.u1() != 'F'.code) {
            throw ParseException("not an ELF file (bad magic)")
        }
        val elfClass = r.u1()
        if (elfClass != 1 && elfClass != 2) throw ParseException("unknown EI_CLASS=$elfClass")
        val endian = r.u1()
        if (endian != 1) throw ParseException("only little-endian ELF supported (EI_DATA=$endian)")
        r.u1() // EI_VERSION
        r.u1() // EI_OSABI
        r.skip(8) // padding
        val type = r.u2()
        val machine = r.u2()
        r.u4() // e_version

        if (elfClass == 2) {
            r.u8(); r.u8() // e_entry, e_phoff
        } else {
            r.u4(); r.u4()
        }
        val shoff = if (elfClass == 2) r.u8() else (r.u4().toLong() and 0xffffffffL)
        r.u4() // e_flags
        r.u2(); r.u2(); r.u2() // ehsize, phentsize, phnum
        r.u2() // e_shentsize
        val shentsize = r.u2()
        val shnum = r.u2()
        val shstrndx = r.u2()

        if (shnum == 0 || shoff == 0L) {
            return ElfFile(elfClass, true, machine, type, emptyList(), emptyMap(), bytes, readBuildId(emptyList(), bytes))
        }

        val actualShnum: Int
        val actualShstrndx: Int
        if (shnum.toInt() == 0 || shstrndx == 0xffff) {
            r.seek(shoff.toInt())
            if (elfClass == 2) {
                r.u4(); r.u4(); r.u8(); r.u8()
                actualShnum = r.u8().toInt()
                r.u8()
                actualShstrndx = r.u4()
            } else {
                r.u4(); r.u4(); r.u4()
                actualShnum = r.u4()
                r.u4()
                actualShstrndx = r.u4()
            }
        } else {
            actualShnum = shnum.toInt()
            actualShstrndx = shstrndx
        }

        if (shoff > Int.MAX_VALUE.toLong() || shoff + actualShnum.toLong() * shentsize > bytes.size.toLong()) {
            throw ParseException("section header table out of bounds")
        }

        data class Raw(
            val nameOff: Int, val stype: Int, val flags: Long, val addr: Long,
            val offset: Long, val size: Long, val link: Int, val info: Int, val align: Long,
        )

        val raws = ArrayList<Raw>(actualShnum)
        for (i in 0 until actualShnum) {
            r.seek((shoff + i.toLong() * shentsize).toInt())
            if (elfClass == 2) {
                val nameOff = r.u4(); val stype = r.u4(); val flags = r.u8(); val addr = r.u8()
                val off = r.u8(); val size = r.u8(); val link = r.u4(); val info = r.u4(); val align = r.u8()
                raws.add(Raw(nameOff, stype, flags, addr, off, size, link, info, align))
            } else {
                val nameOff = r.u4(); val stype = r.u4()
                val flags = r.u4().toLong() and 0xffffffffL
                val addr = r.u4().toLong() and 0xffffffffL
                val off = r.u4().toLong() and 0xffffffffL
                val size = r.u4().toLong() and 0xffffffffL
                val link = r.u4(); val info = r.u4()
                val align = r.u4().toLong() and 0xffffffffL
                raws.add(Raw(nameOff, stype, flags, addr, off, size, link, info, align))
            }
        }

        fun strAt(index: Int): String {
            if (actualShstrndx <= 0 || actualShstrndx >= raws.size) return ""
            val sh = raws[actualShstrndx]
            if (sh.offset + index > bytes.size) return ""
            val start = (sh.offset + index).toInt()
            var end = start
            while (end < bytes.size && bytes[end].toInt() != 0) end++
            return String(bytes, start, end - start, Charsets.UTF_8)
        }

        val sections = raws.mapIndexed { i, x ->
            ElfSection(x.let { strAt(it.nameOff) }, x.stype, x.flags, x.addr, x.offset.toInt(),
                x.size.toInt(), x.link, x.info, x.align, i)
        }
        val byName = sections.filter { it.name.isNotEmpty() }.associateBy { it.name }
        return ElfFile(elfClass, true, machine, type, sections, byName, bytes, readBuildId(sections, bytes))
    }

    private fun readBuildId(sections: List<ElfSection>, bytes: ByteArray): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        return try {
            if (note.offset + note.size > bytes.size) return null
            val r = ByteReader(bytes, note.offset, note.offset + note.size, note.offset)
            while (r.remaining() >= 12) {
                val namesz = r.u4()
                val descsz = r.u4()
                val noteType = r.u4()
                val name = r.bytes(namesz)
                while ((r.pos - note.offset) % 4 != 0 && r.remaining() > 0) r.u1()
                val desc = r.bytes(descsz)
                if (noteType == 3 && String(name).trimEnd(' ') == "GNU" && descsz >= 8) {
                    return desc.joinToString("") { "%02x".format(it) }
                }
                while ((r.pos - note.offset) % 4 != 0 && r.remaining() > 0) r.u1()
            }
            null
        } catch (_: ParseException) {
            null
        }
    }
}
