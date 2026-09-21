@file:Suppress("ArrayInDataClass")
package compass.fixture

import java.io.ByteArrayOutputStream

/**
 * Writes a minimal little-endian 64-bit ELF with arbitrary sections, program headers and
 * optional GNU build-id / symbols. Just enough for compass.elf.ElfParser to read.
 */
class ElfWriter(
    private val machine: Int = 0x3e, // EM_X86_64
    private val entry: Long = 0x400000
) {
    class Section(val name: String, val type: Int, val flags: Long, val addr: Long,
                  val data: ByteArray, val link: Int = 0, val info: Int = 0,
                  val addralign: Long = 1, val entsize: Long = 0)

    class Segment(val type: Int, val type2: Int = 0, val offset: Long, val vaddr: Long, val filesz: Long,
                  val memsz: Long, val flags: Int = 5, val paddr: Long = vaddr, val align: Long = 0x1000)

    private val sections = ArrayList<Section>()
    private val segments = ArrayList<Segment>()

    fun addSection(name: String, type: Int = 1, flags: Long = 0,
                   addr: Long = 0, data: ByteArray = ByteArray(0), link: Int = 0, info: Int = 0,
                   addralign: Long = 1, entsize: Long = 0): Int {
        sections += Section(name, type, flags, addr, data, link, info, addralign, entsize)
        return sections.size + 1
    }

    fun addLoadSegment(offset: Long, vaddr: Long, filesz: Long, memsz: Long = filesz, flags: Int = 5) {
        segments += Segment(1, 1, offset, vaddr, filesz, memsz, flags)
    }

    fun build(): ByteArray {
        val nameBaos = java.io.ByteArrayOutputStream()
        nameBaos.write(0)
        val nameOffsets = HashMap<String, Int>()
        for (s in sections) {
            nameOffsets[s.name] = nameBaos.size()
            nameBaos.write(s.name.toByteArray()); nameBaos.write(0)
        }
        val shstr = nameBaos.toByteArray()

        val all = ArrayList<Section>()
        all += Section("", 0, 0, 0, ByteArray(0))
        all += sections
        val shstrIndex = all.size
        all += Section(".shstrtab", 3, 0, 0, shstr)

        val ehsize = 64
        val phentsize = 56
        val shentsize = 64
        var off = ehsize + phentsize * segments.size
        data class Laid(val sec: Section, val offset: Long)
        val laid = ArrayList<Laid>()
        for (s in all) {
            val aligned = (off + (s.addralign - 1).toInt()) and (s.addralign - 1).inv().toInt()
            laid += Laid(s, aligned.toLong())
            off = (aligned + s.data.size).toInt()
        }
        val shoff = ((off + 7) and 7.inv()).toLong()

        val out = ByteArray((shoff + shentsize * all.size).toInt())
        fun w16(o: Int, v: Int) { out[o] = (v and 0xff).toByte(); out[o + 1] = ((v ushr 8) and 0xff).toByte() }
        fun w32(o: Int, v: Long) { for (i in 0..3) out[o + i] = ((v ushr (i * 8)) and 0xff).toByte() }
        fun w64(o: Int, v: Long) { for (i in 0..7) out[o + i] = ((v ushr (i * 8)) and 0xff).toByte() }

        out[0] = 0x7f; out[1] = 'E'.code.toByte(); out[2] = 'L'.code.toByte(); out[3] = 'F'.code.toByte()
        out[4] = 2; out[5] = 1; out[6] = 1
        w16(16, 2)
        w16(18, machine)
        w32(20, 1)
        w64(24, entry)
        w64(32, if (segments.isEmpty()) 0 else ehsize.toLong())
        w64(40, shoff)
        w32(48, 0)
        w16(52, ehsize)
        w16(54, phentsize)
        w16(56, segments.size)
        w16(58, shentsize)
        w16(60, all.size)
        w16(62, shstrIndex)

        segments.forEachIndexed { i, seg ->
            val o = ehsize + i * phentsize
            w32(o, seg.type.toLong())
            w32(o + 4, seg.flags.toLong())
            w64(o + 8, seg.offset)
            w64(o + 16, seg.vaddr)
            w64(o + 24, seg.paddr)
            w64(o + 32, seg.filesz)
            w64(o + 40, seg.memsz)
            w64(o + 48, seg.align)
        }

        for (l in laid) System.arraycopy(l.sec.data, 0, out, l.offset.toInt(), l.sec.data.size)
        for ((i, l) in laid.withIndex()) {
            val s = l.sec
            val o = (shoff + i * shentsize).toInt()
            w32(o, (nameOffsets[s.name] ?: 0).toLong())
            w32(o + 4, s.type.toLong())
            w64(o + 8, s.flags)
            w64(o + 16, s.addr)
            w64(o + 24, l.offset)
            w64(o + 32, s.data.size.toLong())
            w32(o + 40, s.link.toLong())
            w32(o + 44, s.info.toLong())
            w64(o + 48, s.addralign)
            w64(o + 56, s.entsize)
        }
        return out
    }
}
