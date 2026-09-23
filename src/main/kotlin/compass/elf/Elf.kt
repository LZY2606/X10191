package compass.elf

import compass.bin.DwarfException
import compass.bin.Reader

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val bytes: ByteArray
)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val sections: List<ElfSection>,
    /** Lowest p_vaddr of PT_LOAD segments; link-time base used for load-bias math. */
    val linkBase: Long
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
}

object ElfParser {
    private const val PT_LOAD = 1L

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw DwarfException("not an ELF file")
        val is64 = bytes[4].toInt() == 2
        val little = when (bytes[5].toInt()) {
            1 -> true
            2 -> false
            else -> throw DwarfException("bad ELF data encoding")
        }
        val r = Reader(bytes, littleEndian = little, ctx = "elf")
        r.pos = if (is64) 0x18 else 0x14 // skip ident+type+machine+version
        // We need e_phoff/e_shoff etc.; read header fields by absolute offsets instead.
        fun u16At(off: Int) = Reader(bytes, off, bytes.size, little, "elf").u16()
        fun u32At(off: Int) = Reader(bytes, off, bytes.size, little, "elf").u32()
        fun u64At(off: Int) = Reader(bytes, off, bytes.size, little, "elf").u64()
        fun addrAt(off: Int) = if (is64) u64At(off) else u32At(off)

        val phoff = addrAt(if (is64) 0x20 else 0x1C)
        val shoff = addrAt(if (is64) 0x28 else 0x20)
        val phentsize = u16At(if (is64) 0x36 else 0x2A).toLong()
        val phnum = u16At(if (is64) 0x38 else 0x2C).toLong()
        val shentsize = u16At(if (is64) 0x3A else 0x2E).toLong()
        val shnum = u16At(if (is64) 0x3C else 0x30).toLong()
        val shstrndx = u16At(if (is64) 0x3E else 0x32).toLong()

        if (shoff == 0L || shnum == 0L) throw DwarfException("ELF has no section headers")
        if (shoff + shnum * shentsize > bytes.size) throw DwarfException("section header table out of bounds")

        data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
        val raw = ArrayList<RawSh>()
        for (i in 0 until shnum) {
            val base = (shoff + i * shentsize).toInt()
            val nameOff = u32At(base)
            val type = u32At(base + 4)
            val addr = addrAt(base + if (is64) 0x10 else 0x0C)
            val off = addrAt(base + if (is64) 0x18 else 0x10)
            val size = addrAt(base + if (is64) 0x20 else 0x14)
            raw.add(RawSh(nameOff, type, addr, off, size))
        }
        if (shstrndx >= raw.size) throw DwarfException("bad shstrndx")
        val strTab = raw[shstrndx.toInt()]
        if (strTab.off + strTab.size > bytes.size) throw DwarfException("shstrtab out of bounds")

        fun strAt(off: Long): String {
            var p = (strTab.off + off).toInt()
            val end = (strTab.off + strTab.size).toInt()
            val sb = StringBuilder()
            while (p < end && bytes[p].toInt() != 0) { sb.append(bytes[p].toInt().toChar()); p++ }
            return sb.toString()
        }

        val sections = raw.map { sh ->
            val end = sh.off + sh.size
            val content = if (sh.type == 8L /* SHT_NOBITS */ || sh.size == 0L) ByteArray(0)
            else {
                if (end > bytes.size) throw DwarfException("section ${sh.nameOff} out of bounds")
                bytes.copyOfRange(sh.off.toInt(), end.toInt())
            }
            ElfSection(strAt(sh.nameOff), sh.type, sh.addr, sh.off, sh.size, content)
        }

        var linkBase = 0L
        if (phoff != 0L && phnum > 0) {
            var minV: Long? = null
            for (i in 0 until phnum) {
                val base = (phoff + i * phentsize).toInt()
                if (base + phentsize > bytes.size) break
                val ptype = u32At(base)
                if (ptype != PT_LOAD) continue
                val vaddr = if (is64) u64At(base + 0x10) else u32At(base + 0x08)
                minV = if (minV == null) vaddr else minOf(minV!!, vaddr)
            }
            linkBase = minV ?: 0L
        }
        return ElfFile(is64, little, sections, linkBase)
    }
}
