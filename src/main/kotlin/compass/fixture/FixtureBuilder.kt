package compass.fixture

import java.io.ByteArrayOutputStream
import java.nio.ByteOrder

/**
 * 极小 ELF64 + DWARF section 构造器。
 *
 * 不是系统工具输出，而是按规范逐字节拼装，便于精确制造边界场景：
 * special opcode、end_sequence、多 sequence、重叠范围、high_pc 两种含义、
 * DWARF4/5 混用、分段地址、零长度范围、缺 dwo、未知 form、越界引用。
 */
class FixtureBuilder {
    private val sections = LinkedHashMap<String, ByteArray>()
    private var shStrTab: ByteArray = ByteArray(0)

    fun section(name: String, data: ByteArray): FixtureBuilder { sections[name] = data; return this }

    fun build(endian: ByteOrder = ByteOrder.LITTLE_ENDIAN): ByteArray {
        val names = ArrayList<String>(sections.keys + listOf("", ".shstrtab"))
        val nameIndex = LinkedHashMap<String, Int>()
        val shstr = ByteArrayOutputStream()
        shstr.write(0)
        for (n in names) { if (n.isEmpty() || n == ".shstrtab") continue; nameIndex[n] = shstr.size(); shstr.write(n.toByteArray()); shstr.write(0) }
        nameIndex[".shstrtab"] = shstr.size(); shstr.write(".shstrtab".toByteArray()); shstr.write(0)
        shStrTab = shstr.toByteArray()

        val le = endian == ByteOrder.LITTLE_ENDIAN
        fun put2(b: ByteArrayOutputStream, v: Int) { b.write(v and 0xff); b.write((v ushr 8) and 0xff) }
        fun put4(b: ByteArrayOutputStream, v: Int) {
            if (le) { b.write(v and 0xff); b.write((v ushr 8) and 0xff); b.write((v ushr 16) and 0xff); b.write((v ushr 24) and 0xff) }
            else { b.write((v ushr 24) and 0xff); b.write((v ushr 16) and 0xff); b.write((v ushr 8) and 0xff); b.write(v and 0xff) }
        }
        fun put8(b: ByteArrayOutputStream, v: Long) {
            val bb = java.nio.ByteBuffer.allocate(8).order(endian).putLong(v).array()
            b.write(bb)
        }

        // section 数据布局
        val ehsize = 64
        val shentsize = 64
        var off = ehsize
        data class Placed(val name: String, val data: ByteArray, var off: Long)
        val placed = ArrayList<Placed>()
        for ((n, d) in sections.entries) { placed.add(Placed(n, d, off.toLong())); off += d.size }
        val shstrPlaced = Placed(".shstrtab", shStrTab, off.toLong()); off += shStrTab.size
        val shoff = off.toLong()

        val all = ArrayList<Placed>()
        all.add(Placed("", ByteArray(0), 0))
        all.addAll(placed)
        all.add(shstrPlaced)
        val shnum = all.size
        val shstrndx = all.indexOf(shstrPlaced)

        val out = ByteArrayOutputStream()
        // ELF64 header
        out.write(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        out.write(2) // ELFCLASS64
        out.write(if (le) 1 else 2)
        out.write(1) // EV_CURRENT
        out.write(0)
        repeat(8) { out.write(0) }
        put2(out, 2)     // ET_EXEC
        put2(out, 62)    // EM_X86_64
        put4(out, 1)     // e_version
        put8(out, 0x400000) // e_entry
        put8(out, 0)     // e_phoff
        put8(out, shoff)
        put4(out, 0)     // e_flags
        put2(out, ehsize)
        put2(out, 0); put2(out, 0) // phentsize, phnum
        put2(out, shentsize)
        put2(out, shnum)
        put2(out, shstrndx)
        check(out.size() == ehsize)
        for (p in placed) { out.write(p.data); check(p.off == (out.size() - p.data.size).toLong()) }
        out.write(shStrTab)
        check(out.size().toLong() == shoff)

        for ((idx, p) in all.withIndex()) {
            val sh = ByteArrayOutputStream()
            put4(sh, if (p.name.isEmpty()) 0 else nameIndex[p.name] ?: 0)
            put4(sh, if (p.name.isEmpty()) 0 else 1) // SHT_PROGBITS
            put8(sh, 0) // flags
            put8(sh, if (p.name.startsWith(".debug")) 0L else 0L) // addr
            put8(sh, if (p.name.isEmpty()) 0L else p.off)
            put8(sh, p.data.size.toLong())
            put4(sh, 0) // link
            put4(sh, 0) // info
            put8(sh, 1) // addralign
            put8(sh, 0) // entsize
            check(sh.size() == shentsize)
            out.write(sh.toByteArray())
        }
        return out.toByteArray()
    }
}

/** 小端 DWARF 字节构造助手。 */
class DwarfBuf(private val le: Boolean = true) {
    val out = ByteArrayOutputStream()
    private fun u4(v: Int) {
        if (le) { out.write(v and 0xff); out.write((v ushr 8) and 0xff); out.write((v ushr 16) and 0xff); out.write((v ushr 24) and 0xff) }
        else { out.write((v ushr 24) and 0xff); out.write((v ushr 16) and 0xff); out.write((v ushr 8) and 0xff); out.write(v and 0xff) }
    }
    private fun u2(v: Int) { if (le) { out.write(v and 0xff); out.write((v ushr 8) and 0xff) } else { out.write((v ushr 8) and 0xff); out.write(v and 0xff) } }
    private fun u1(v: Int) { out.write(v and 0xff) }
    private fun u8(v: Long) { out.write(java.nio.ByteBuffer.allocate(8).order(if (le) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN).putLong(v).array()) }
    fun uleb(v: Long) {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x == 0L) { u1(b); break } else u1(b or 0x80)
        }
    }
    fun bytes(b: ByteArray) { out.write(b) }
    fun cstring(s: String) { out.write(s.toByteArray(Charsets.UTF_8)); u1(0) }
    fun u1b(v: Int): DwarfBuf { u1(v); return this }
    fun u2b(v: Int): DwarfBuf { u2(v); return this }
    fun u4b(v: Int): DwarfBuf { u4(v); return this }
    fun u8b(v: Long): DwarfBuf { u8(v); return this }
    fun ulebB(v: Long): DwarfBuf { uleb(v); return this }
    fun bytesB(b: ByteArray): DwarfBuf { bytes(b); return this }
    fun strB(s: String): DwarfBuf { cstring(s); return this }
    fun bytes(): ByteArray = out.toByteArray()
}
