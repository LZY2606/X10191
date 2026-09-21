package compass.fixtures

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Builds a minimal but valid 64-bit little-endian ET_EXEC ELF containing only the
 * sections the DWARF parser needs, plus one PT_LOAD segment so segmented-address
 * translation works. Layout: ELF header | program headers | section data |
 * section headers.
 */
class ElfWriter {
    private data class Section(
        val name: String,
        val type: Int,
        val flags: Long,
        val addr: Long,
        val data: ByteArray,
        val link: Int = 0,
        val info: Int = 0,
        val align: Long = 1,
        val entsize: Long = 0,
    )

    private val sections = ArrayList<Section>()
    private var loadVaddr = 0x400000L
    private var loadFileOffset = 0L

    init {
        // index 0 = null section, implicit
    }

    fun debug(name: String, data: ByteArray, alloc: Boolean = false, addr: Long = 0L) {
        sections += Section(name, 1 /*SHT_PROGBITS*/, if (alloc) 0x6L else 0L, addr, data)
    }

    fun setLoadSegment(vaddr: Long, fileOffset: Long) {
        loadVaddr = vaddr; loadFileOffset = fileOffset
    }

    fun build(): ByteArray {
        // section name string table
        val nameStr = ByteArrayOutputStream()
        nameStr.write(0)
        val nameOffsets = HashMap<String, Int>()
        for (s in sections) {
            nameOffsets[s.name] = nameStr.size()
            nameStr.write(s.name.toByteArray()); nameStr.write(0)
        }
        val shstrtab = nameStr.toByteArray()
        val all = sections + Section(".shstrtab", 3 /*SHT_STRTAB*/, 0, 0, shstrtab)
        val shstrIndex = all.size // last index

        val ehdrSize = 64
        val phentsize = 56
        val phnum = 1
        val phoff = ehdrSize.toLong()
        var cursor = (ehdrSize + phentsize * phnum + 0xf).and(0xf.inv()).toLong()

        // compute section file offsets and addresses for allocated ones
        val offsets = LongArray(all.size)
        val addrs = LongArray(all.size)
        var allocCursor = loadVaddr
        for (i in all.indices) {
            val s = all[i]
            offsets[i] = cursor
            cursor += s.data.size
            if (s.flags and 0x2L != 0L) { // SHF_ALLOC
                addrs[i] = allocCursor
                allocCursor += s.data.size
            }
        }
        val sectionDataEnd = cursor
        val shoff = (sectionDataEnd + 0xf).and(0xf.inv())
        val shentsize = 64
        val shnum = all.size + 1 // +null

        // PT_LOAD spans file from the first allocated section offset
        val firstAlloc = offsets.zip(addrs).firstOrNull { (_, a) -> a != 0L }
        val segFileStart = firstAlloc?.first ?: cursor
        val segVaddr = firstAlloc?.second ?: loadVaddr
        val filesz = (allocCursor - segVaddr).coerceAtLeast(0)

        val total = (shoff + shentsize * shnum).toInt()
        val buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)

        // ELF header
        buf.put(0x7f); buf.put('E'.code.toByte()); buf.put('L'.code.toByte()); buf.put('F'.code.toByte())
        buf.put(2) // 64-bit
        buf.put(1) // little endian
        buf.put(1) // ELF version
        buf.put(0); buf.put(0); buf.put(0); buf.put(0); buf.put(0); buf.put(0); buf.put(0); buf.put(0); buf.put(0)
        buf.short(2) // ET_EXEC
        buf.short(62) // EM_X86_64
        buf.int(1) // version
        buf.long(0x400080) // entry
        buf.long(phoff)
        buf.long(shoff)
        buf.int(0) // flags
        buf.short(ehdrSize)
        buf.short(phentsize)
        buf.short(phnum)
        buf.short(shentsize)
        buf.short(shnum)
        buf.short(shstrIndex)

        // program header (PT_LOAD)
        while (buf.position() < phoff) buf.put(0)
        buf.position(phoff.toInt())
        buf.int(1) // PT_LOAD
        buf.int(5) // PF_R|PF_X
        buf.long(segFileStart)
        buf.long(segVaddr)
        buf.long(segVaddr) // paddr
        buf.long(filesz)
        buf.long(filesz)
        buf.long(0x1000)

        // section data
        for (i in all.indices) {
            buf.position(offsets[i].toInt())
            buf.put(all[i].data)
        }

        // section headers
        buf.position(shoff.toInt())
        // null
        repeat(10) { buf.int(0); }
        // 10 ints == 40 bytes; need 64: add 6 more ints
        repeat(6) { buf.int(0) }
        for (i in all.indices) {
            val s = all[i]
            val isShstr = i == all.lastIndex
            buf.int(nameOffsets[s.name] ?: 0)
            buf.int(s.type)
            buf.long(s.flags)
            buf.long(addrs[i])
            buf.long(offsets[i])
            buf.long(s.data.size.toLong())
            buf.int(if (isShstr) 0 else s.link)
            buf.int(s.info)
            buf.long(if (s.align == 0L) 1 else s.align)
            buf.long(s.entsize)
        }
        return buf.array()
    }

    private fun ByteBuffer.short(v: Int) { putShort(v.toShort()) }
    private fun ByteBuffer.int(v: Int) { putInt(v) }
    private fun ByteBuffer.long(v: Long) { putLong(v) }
}
