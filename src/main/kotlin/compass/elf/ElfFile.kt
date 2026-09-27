package compass.elf

/**
 * Minimal, bounds-checked ELF parser.
 *
 * Supports ELF32/ELF64, little/big endian, and program headers used to
 * compute the load bias (delta between a runtime base and the first
 * PT_LOAD segment vaddr). Section headers provide the raw section bytes
 * consumed by the DWARF layer.
 */
class ElfException(message: String) : RuntimeException(message)

class ByteReader(val data: ByteArray, var pos: Int = 0) {
    val size: Int get() = data.size

    fun require(n: Int) {
        if (pos < 0 || n < 0 || pos > data.size - n) {
            throw ElfException("read out of bounds: pos=$pos need=$n size=${data.size}")
        }
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun u16(): Int {
        require(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (bigEndian) (a shl 8) or b else (b shl 8) or a
    }
    fun u32(): Long {
        require(4)
        var v = 0L
        if (bigEndian) {
            for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }
    fun u64(): Long {
        require(8)
        var v = 0L
        if (bigEndian) {
            for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray { require(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }
    fun cstring(offset: Int): String {
        if (offset < 0 || offset >= data.size) throw ElfException("cstr out of bounds")
        var end = offset
        while (end < data.size && data[end].toInt() != 0) end++
        return String(data, offset, end - offset, Charsets.UTF_8)
    }

    var bigEndian: Boolean = false
}

data class Section(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
) {
    fun bytes(reader: ByteReader): ByteArray {
        if (offset < 0 || size < 0 || offset > reader.data.size - size) {
            throw ElfException("section '$name' bytes out of bounds: off=$offset size=$size file=${reader.data.size}")
        }
        return reader.data.copyOfRange(offset.toInt(), (offset + size).toInt())
    }
}

data class ProgramSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class ElfFile(
    val elfClass: Int,
    val littleEndian: Boolean,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<Section>,
    val segments: List<ProgramSegment>,
    val raw: ByteArray,
    val sha256: String,
) {
    val is64 get() = elfClass == 2

    fun section(name: String): Section? = sections.firstOrNull { it.name == name }
    fun sectionBytes(name: String): ByteArray? = section(name)?.let {
        it.bytes(ByteReader(raw).also { r -> r.bigEndian = !littleEndian })
    }

    /**
     * Load bias applied when the file is mapped at [base]: runtime address
     * `vma = bias + fileVaddr`. For ET_DYN the kernel maps the first PT_LOAD
     * at the runtime base; ET_EXEC is fixed, bias is 0.
     */
    fun loadBias(base: Long): Long {
        if (type != ET_DYN) return 0L
        val firstLoad = segments.filter { it.type == PT_LOAD }.minByOrNull { it.vaddr }
            ?: return base
        return base - firstLoad.vaddr
    }

    /** Lowest mapped runtime vaddr of any PT_LOAD. */
    fun lowestLoadVaddr(): Long? =
        segments.filter { it.type == PT_LOAD }.minOfOrNull { it.vaddr }

    companion object {
        const val ET_NONE = 0
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val PT_LOAD = 1
    }
}

object ElfParser {
    private const val MAGIC = 0x7f454c46 // \x7fELF

    fun parse(data: ByteArray, sha256: String): ElfFile {
        if (data.size < 64) throw ElfException("file too small for ELF header")
        val r = ByteReader(data)
        val magic = run {
            var v = 0
            for (i in 0 until 4) v = (v shl 8) or (data[i].toInt() and 0xff)
            v
        }
        if (magic != MAGIC) throw ElfException("bad ELF magic")
        val elfClass = data[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw ElfException("bad EI_CLASS=$elfClass")
        val dataEncoding = data[5].toInt() and 0xff
        if (dataEncoding != 1 && dataEncoding != 2) throw ElfException("bad EI_DATA=$dataEncoding")
        r.bigEndian = dataEncoding == 2
        r.pos = 16
        val type = r.u16()
        val machine = r.u16()
        r.u32() // e_version
        val entry: Long
        val phoff: Long
        val shoff: Long
        if (elfClass == 2) {
            entry = r.u64()
            phoff = r.u64()
            shoff = r.u64()
        } else {
            entry = r.u32()
            phoff = r.u32()
            shoff = r.u32()
        }
        r.u32() // e_flags
        r.u16() // e_ehsize
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val segments = ArrayList<ProgramSegment>(phnum)
        repeat(phnum) { i ->
            r.pos = (phoff + i.toLong() * phentsize).toInt()
            segments += if (elfClass == 2) {
                val pType = r.u32()
                val pFlags = r.u32()
                val pOffset = r.u64()
                val pVaddr = r.u64()
                val pPaddr = r.u64()
                val pFilesz = r.u64()
                val pMemsz = r.u64()
                val pAlign = r.u64()
                ProgramSegment(pType, pFlags, pOffset, pVaddr, pPaddr, pFilesz, pMemsz, pAlign)
            } else {
                val pType = r.u32()
                val pOffset = r.u32()
                val pVaddr = r.u32()
                val pPaddr = r.u32()
                val pFilesz = r.u32()
                val pMemsz = r.u32()
                val pFlags = r.u32()
                val pAlign = r.u32()
                ProgramSegment(pType, pFlags, pOffset, pVaddr, pPaddr, pFilesz, pMemsz, pAlign)
            }
        }

        val rawSections = ArrayList<Section>(shnum)
        repeat(shnum) { i ->
            r.pos = (shoff + i.toLong() * shentsize).toInt()
            rawSections += if (elfClass == 2) {
                val nameOff = r.u32().toInt()
                val sType = r.u32()
                val sFlags = r.u64()
                val sAddr = r.u64()
                val sOff = r.u64()
                val sSize = r.u64()
                val sLink = r.u32()
                val sInfo = r.u32()
                val sAlign = r.u64()
                r.u64() // entsize
                Section("", sType, sFlags, sAddr, sOff, sSize, sLink, sInfo, sAlign)
            } else {
                val nameOff = r.u32().toInt()
                val sType = r.u32()
                val sFlags = r.u32()
                val sAddr = r.u32()
                val sOff = r.u32()
                val sSize = r.u32()
                val sLink = r.u32()
                val sInfo = r.u32()
                val sAlign = r.u32()
                r.u32() // entsize
                Section("", sType, sFlags.toLong(), sAddr, sOff, sSize.toLong(), sLink, sInfo, sAlign.toLong())
            }.copy(name = "__off_$nameOff")
        }

        val shstrtab = if (shstrndx in rawSections.indices) rawSections[shstrndx] else null
        val nameReader = if (shstrtab != null) {
            val nr = ByteReader(data)
            nr.bigEndian = dataEncoding == 2
            nr.pos = shstrtab.offset.toInt()
            nr
        } else null

        val sections = rawSections.map { s ->
            val name = if (nameReader != null) {
                val off = s.name.removePrefix("__off_").toInt()
                runCatching { nameReader.cstring(off) }.getOrDefault("")
            } else ""
            s.copy(name = name)
        }

        return ElfFile(elfClass, dataEncoding == 1, type, machine, entry, sections, segments, data, sha256)
    }
}
