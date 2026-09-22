@file:Suppress("ArrayInDataClass")
package compass.fixture

import java.io.ByteArrayOutputStream

/** Builds a minimal little-endian 64-bit ELF file from named section blobs. */
class ElfWriter(
    private val entry: Long = 0x400000,
    private val loadableRanges: List<LongRange> = listOf(0x400000L..0x500000L)
) {
    data class Section(
        val name: String,
        val data: ByteArray,
        val type: Int = 1, // SHT_PROGBITS
        val flags: Long = 0,
        val addr: Long = 0,
        val link: Int = 0,
        val entsize: Long = 0
    )

    fun build(sections: List<Section>): ByteArray {
        // assemble shstrtab
        val nameTab = ByteArrayOutputStream()
        nameTab.write(0)
        val nameOffsets = HashMap<String, Int>()
        for (s in sections) {
            if (s.name in nameOffsets) continue
            nameOffsets[s.name] = nameTab.size()
            nameTab.write(s.name.toByteArray())
            nameTab.write(0)
        }
        val shstr = nameTab.toByteArray()
        val all = sections + Section(".shstrtab", shstr, type = 3 /*STRTAB*/)
        val shstrndx = all.size - 1

        // ELF header
        val eh = ByteArray(64)
        eh[0] = 0x7f; eh[1] = 'E'.code.toByte(); eh[2] = 'L'.code.toByte(); eh[3] = 'F'.code.toByte()
        eh[4] = 2 // ELFCLASS64
        eh[5] = 1 // little endian
        eh[6] = 1 // EV_CURRENT
        eh[7] = 0
        // e_type ET_EXEC=2, machine x86-64=62, e_version=1
        putU16(eh, 16, 2)
        putU16(eh, 18, 62)
        putU32(eh, 20, 1)
        putU64(eh, 24, entry)
        // phoff = 64
        putU64(eh, 32, 64)
        // shoff filled later
        putU16(eh, 52, 64) // ehsize
        putU16(eh, 54, 56) // phentsize
        putU16(eh, 56, loadableRanges.size) // phnum
        putU16(eh, 58, 64) // shentsize
        putU16(eh, 60, all.size + 1) // shnum incl null
        putU16(eh, 62, shstrndx + 1)

        // program headers: one PT_LOAD per given range
        val ph = ByteArrayOutputStream()
        for (range in loadableRanges) {
            val p = ByteArray(56)
            putU32(p, 0, 1) // PT_LOAD
            putU32(p, 4, 5) // R+X
            putU64(p, 8, range.first) // offset
            putU64(p, 16, range.first) // vaddr
            putU64(p, 24, range.first) // paddr
            putU64(p, 32, range.last - range.first + 1) // filesz
            putU64(p, 40, range.last - range.first + 1) // memsz
            putU64(p, 48, 0x1000)
            ph.write(p)
        }

        // layout sections after headers
        var cursor = 64 + ph.size()
        data class Placed(val s: Section, val off: Long, val nameOff: Int)
        val placed = all.map { s ->
            val aligned = (cursor + 7) and 7.inv()
            val nameOff = nameOffsets[s.name] ?: 0
            val pl = Placed(s, aligned.toLong(), nameOff)
            cursor = aligned + s.data.size
            pl
        }
        val shoff = (cursor + 7) and 7.inv()
        putU64(eh, 40, shoff.toLong())

        val out = ByteArray(shoff + (all.size + 1) * 64)
        System.arraycopy(eh, 0, out, 0, eh.size)
        System.arraycopy(ph.toByteArray(), 0, out, 64, ph.size())
        for (p in placed) System.arraycopy(p.s.data, 0, out, p.off.toInt(), p.s.data.size)

        // section headers: null first
        var sh = shoff
        sh += 64
        for (p in placed) {
            val s = p.s
            putU32(out, sh, p.nameOff)
            putU32(out, sh + 4, s.type)
            putU64(out, sh + 8, s.flags)
            putU64(out, sh + 16, s.addr)
            putU64(out, sh + 24, p.off)
            putU64(out, sh + 32, s.data.size.toLong())
            putU32(out, sh + 40, s.link)
            putU32(out, sh + 44, 0)
            putU64(out, sh + 48, 1)
            putU64(out, sh + 56, s.entsize)
            sh += 64
        }
        return out
    }

    companion object {
        fun putU16(b: ByteArray, o: Int, v: Int) { b[o] = (v and 0xff).toByte(); b[o + 1] = ((v ushr 8) and 0xff).toByte() }
        fun putU32(b: ByteArray, o: Int, v: Int) { for (i in 0..3) b[o + i] = ((v ushr (8 * i)) and 0xff).toByte() }
        fun putU64(b: ByteArray, o: Int, v: Long) { for (i in 0..7) b[o + i] = ((v ushr (8 * i)) and 0xff).toByte() }
    }
}
