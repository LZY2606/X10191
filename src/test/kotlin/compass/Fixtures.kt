package compass

import java.io.ByteArrayOutputStream

/** 小端字节构造器。 */
class Bin {
    private val out = ByteArrayOutputStream()
    val size: Int get() = out.size()
    fun u8(v: Int): Bin { out.write(v and 0xff); return this }
    fun u16(v: Int): Bin { out.write(v and 0xff); out.write((v ushr 8) and 0xff); return this }
    fun u32(v: Long): Bin { repeat(4) { i -> out.write((v ushr (8 * i)).toInt() and 0xff) }; return this }
    fun u64(v: Long): Bin { repeat(8) { i -> out.write((v ushr (8 * i)).toInt() and 0xff) }; return this }
    fun bytes(b: ByteArray): Bin { out.write(b); return this }
    fun str(s: String): Bin { out.write(s.toByteArray()); out.write(0); return this }
    fun uleb(v: Long): Bin {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x == 0L) { out.write(b); return this }
            out.write(b or 0x80)
        }
    }
    fun sleb(v: Long): Bin {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40 != 0
            x = x shr 7
            if ((x == 0L && !sign) || (x == -1L && sign)) { out.write(b); return this }
            out.write(b or 0x80)
        }
    }
    fun build(): ByteArray = out.toByteArray()
}

/**
 * 极小 ELF64 小端可执行文件构造器：ELF header + 0 个 program header + N 个 section header。
 * 只服务于测试，不追求可被系统加载。
 */
class TinyElf {
    private data class Sec(val name: String, val data: ByteArray, val type: Int = 1, val addr: Long = 0, val link: Int = 0, val entsize: Long = 0)
    private val sections = ArrayList<Sec>()
    private val relocs = ArrayList<Triple<String, ByteArray, Boolean>>() // target, rela bytes, rela

    fun section(name: String, data: ByteArray, addr: Long = 0, type: Int = 1, link: Int = 0, entsize: Long = 0): TinyElf {
        sections += Sec(name, data, type, addr, link, entsize); return this
    }

    /** 追加一个针对 [target] section 的 RELA 重定位 section（小端 x86-64 语义）。 */
    fun rela(target: String, entries: List<Triple<Long, Long, Long>>): TinyElf {
        val b = Bin()
        for ((off, info, addend) in entries) b.u64(off).u64(info).u64(addend)
        relocs += Triple(".rela$target", b.build(), true)
        return this
    }

    fun build(): ByteArray {
        val shstr = Bin()
        val nameOffsets = HashMap<String, Int>()
        shstr.u8(0)
        val allNames = (sections.map { it.name } + relocs.map { it.first } + ".shstrtab").distinct()
        for (n in allNames) { nameOffsets[n] = shstr.size; shstr.str(n) }
        val shstrBytes = shstr.build()

        val ordered = ArrayList(sections)
        for (r in relocs) ordered += Sec(r.first, r.second, type = 4)
        ordered += Sec(".shstrtab", shstrBytes, type = 3)

        val shnum = ordered.size + 1
        val shentsize = 64
        val ehsize = 64
        var cur = ehsize
        data class Placed(val sec: Sec, val off: Long)
        val placed = ordered.map { sec ->
            val off = if (sec.type == 8) 0L else cur.toLong()
            cur += sec.data.size
            Placed(sec, off)
        }
        val shoff = cur
        val targetIndex = HashMap<String, Int>()
        placed.forEachIndexed { i, p -> targetIndex[p.sec.name] = i + 1 }

        val out = Bin()
        // ---- ELF header ----
        out.bytes(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        out.u8(2)   // 64-bit
        out.u8(1)   // little endian
        out.u8(1)   // ELF version
        out.u8(0)   // osabi
        repeat(8) { out.u8(0) }
        out.u16(2)  // ET_EXEC
        out.u16(0x3e) // x86-64
        out.u32(1)
        out.u64(0x1000) // e_entry
        out.u64(0)     // e_phoff
        out.u64(shoff.toLong()) // e_shoff
        out.u32(0)     // e_flags
        out.u16(ehsize) // e_ehsize
        out.u16(0)     // e_phentsize
        out.u16(0)     // e_phnum
        out.u16(shentsize) // e_shentsize
        out.u16(shnum)     // e_shnum
        out.u16(targetIndex[".shstrtab"] ?: 0) // e_shstrndx
        check(out.size == ehsize) { "ELF header 大小应为 64，实际 ${out.size}" }

        for (p in placed) out.bytes(p.sec.data)

        fun sh(name: String, type: Int, flags: Long, addr: Long, off: Long, size: Long, link: Int, info: Int, addralign: Long, entsize: Long) {
            out.u32((nameOffsets[name] ?: 0).toLong())
            out.u32(type.toLong())
            out.u64(flags)
            out.u64(addr)
            out.u64(off)
            out.u64(size)
            out.u32(link.toLong())
            out.u32(info.toLong())
            out.u64(addralign)
            out.u64(entsize)
        }
        // null section
        sh("", 0, 0, 0, 0, 0, 0, 0, 0, 0)
        for (p in placed) {
            val sec = p.sec
            val link = if (sec.name.startsWith(".rela")) (targetIndex[".symtab"] ?: 0) else sec.link
            val info = if (sec.name.startsWith(".rela")) (targetIndex[sec.name.removePrefix(".rela")] ?: 0) else 0
            sh(sec.name, sec.type, if (sec.addr != 0L) 0x2L else 0L, sec.addr,
                if (sec.type == 8) 0 else p.off, sec.data.size.toLong(), link, info, 1, sec.entsize)
        }
        return out.build()
    }
}
