package com.compass.dwarf

/** ELF program header (PT_LOAD used for load-bias resolution). */
data class ProgSeg(val type: Int, val flags: Int, val offset: Long, val vaddr: Long, val paddr: Long,
                   val filesz: Long, val memsz: Long, val align: Long, val segmentIndex: Int)

/** One ELF section header plus its raw bytes. */
data class Section(val name: String, val type: Int, val flags: Long, val addr: Long,
                   val fileOffset: Long, val size: Long, val link: Int, val info: Int,
                   val addralign: Long, val entsize: Long, val index: Int, val data: ByteArray) {
    fun buf(): Buf = Buf(data)
    override fun equals(other: Any?) = other is Section && index == other.index
    override fun hashCode() = index
}

/** Parsed ELF container: sections by name and PT_LOAD segments. */
class ElfFile(val bytes: ByteArray) {
    val is64: Boolean
    val littleEndian: Boolean
    val elfType: Int
    val machine: Int
    val sections = mutableListOf<Section>()
    val byName = linkedMapOf<String, Section>()
    val segments = mutableListOf<ProgSeg>()
    val parseIssues = mutableListOf<ParseIssue>()

    val sha256: String by lazy {
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun u16(o: Int): Int = if (littleEndian)
        (bytes[o].toInt() and 0xff) or ((bytes[o + 1].toInt() and 0xff) shl 8)
    else ((bytes[o].toInt() and 0xff) shl 8) or (bytes[o + 1].toInt() and 0xff)

    private fun u32(o: Int): Long {
        var v = 0L
        for (i in 0 until 4) {
            val b = bytes[o + i].toLong() and 0xff
            v = v or (if (littleEndian) b shl (i * 8) else b shl ((3 - i) * 8))
        }
        return v
    }

    private fun u64(o: Int): Long {
        var v = 0L
        for (i in 0 until 8) {
            val b = bytes[o + i].toLong() and 0xff
            v = v or (if (littleEndian) b shl (i * 8) else b shl ((7 - i) * 8))
        }
        return v
    }

    init {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ParseException("not an ELF file (bad magic)")
        val cls = bytes[4].toInt() and 0xff
        is64 = cls == 2
        if (cls != 1 && cls != 2) throw ParseException("invalid ELF class $cls")
        val enc = bytes[5].toInt() and 0xff
        littleEndian = enc == 1
        if (enc != 1 && enc != 2) throw ParseException("invalid ELF data encoding $enc")

        elfType = u16(16); machine = u16(18)
        if (is64) parse64() else parse32()
        for (s in sections) byName.putIfAbsent(s.name, s)
    }

    private fun parse64() {
        val phOff = u64(32); val phEnt = u16(54); val phNum = u16(56)
        val shOff = u64(40); val shEnt = u16(58); val shNum = u16(60); val shStrNdx = u16(62)
        for (i in 0 until phNum) {
            val o = (phOff + i * phEnt).toInt()
            if (o < 0 || o + 56 > bytes.size) { parseIssues += ParseIssue("elf", "program header $i out of bounds", "error"); continue }
            segments += ProgSeg(u32(o).toInt(), u32(o + 4).toInt(), u64(o + 8), u64(o + 16),
                u64(o + 24), u64(o + 32), u64(o + 40), u64(o + 48), i)
        }
        val shStr = readShStr(shOff, shEnt, shNum, shStrNdx, is64 = true)
        for (i in 0 until shNum) {
            val o = (shOff + i * shEnt).toInt()
            if (o < 0 || o + 64 > bytes.size) { parseIssues += ParseIssue("elf", "section header $i out of bounds", "error"); continue }
            val nm = strName(shStr, u32(o))
            sections += Section(nm, u32(o + 4).toInt(), u64(o + 8), u64(o + 16),
                u64(o + 24), u64(o + 32), u32(o + 40).toInt(), u32(o + 44).toInt(),
                u64(o + 48), u64(o + 56), i, sliceOf(u64(o + 24), u64(o + 32)))
        }
    }

    private fun parse32() {
        val phOff = u32(28); val phEnt = u16(42); val phNum = u16(44)
        val shOff = u32(32); val shEnt = u16(46); val shNum = u16(48); val shStrNdx = u16(50)
        for (i in 0 until phNum) {
            val o = (phOff + i * phEnt).toInt()
            if (o < 0 || o + 32 > bytes.size) { parseIssues += ParseIssue("elf", "program header $i out of bounds", "error"); continue }
            segments += ProgSeg(u32(o).toInt(), u32(o + 24).toInt(), u32(o + 4), u32(o + 8),
                u32(o + 12), u32(o + 16), u32(o + 20), u32(o + 28), i)
        }
        val shStr = readShStr(shOff, shEnt, shNum, shStrNdx, is64 = false)
        for (i in 0 until shNum) {
            val o = (shOff + i * shEnt).toInt()
            if (o < 0 || o + 40 > bytes.size) { parseIssues += ParseIssue("elf", "section header $i out of bounds", "error"); continue }
            val nm = strName(shStr, u32(o))
            sections += Section(nm, u32(o + 4).toInt(), u32(o + 8), u32(o + 12),
                u32(o + 16), u32(o + 20), u32(o + 24).toInt(), u32(o + 28).toInt(),
                u32(o + 32), u32(o + 36), i, sliceOf(u32(o + 16), u32(o + 20)))
        }
    }

    private fun readShStr(shOff: Long, shEnt: Int, shNum: Int, shStrNdx: Int, is64: Boolean): ByteArray {
        if (shStrNdx == 0 || shStrNdx >= shNum) return ByteArray(0)
        val o = (shOff + shStrNdx * shEnt).toInt()
        return if (is64) sliceOf(u64(o + 24), u64(o + 32)) else sliceOf(u32(o + 16), u32(o + 20))
    }

    private fun sliceOf(off: Long, len: Long): ByteArray {
        val o = off.toInt(); val n = len.toInt()
        if (o == 0 && n == 0) return ByteArray(0)
        if (o < 0 || n < 0 || o > bytes.size || o + n > bytes.size) return ByteArray(0)
        return bytes.copyOfRange(o, o + n)
    }

    private fun strName(tab: ByteArray, off: Long): String {
        val o = off.toInt()
        if (o < 0 || o >= tab.size) return "<bad:0x${off.toString(16)}>"
        var end = o
        while (end < tab.size && tab[end] != 0.toByte()) end++
        return String(tab, o, end - o, Charsets.UTF_8)
    }

    /** Lowest PT_LOAD vaddr — link-time base for load-bias math. */
    fun linkBase(): Long = segments.filter { it.type == PT_LOAD && it.memsz > 0 }.minOfOrNull { it.vaddr } ?: 0L

    fun section(name: String): Section? = byName[name]

    companion object {
        const val PT_LOAD = 1
    }
}
