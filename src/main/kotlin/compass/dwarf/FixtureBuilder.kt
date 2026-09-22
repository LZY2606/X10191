package compass.dwarf

/** 增量字节构建器：小端整数、LEB128、NUL 字符串。 */
class ByteBuilder {
    private val out = java.io.ByteArrayOutputStream()
    val size: Int get() = out.size()
    fun u8(v: Int) = apply { out.write(v and 0xff) }
    fun u16(v: Int) = apply { out.write(v and 0xff); out.write((v ushr 8) and 0xff) }
    fun u32(v: Long) = apply { repeat(4) { out.write(((v ushr (8 * it)).toInt()) and 0xff) } }
    fun u32Int(v: Int) = u32(v.toLong() and 0xffffffffL)
    fun u64(v: Long) = apply { repeat(8) { out.write(((v ushr (8 * it)).toInt()) and 0xff) } }
    fun bytes(b: ByteArray) = apply { out.write(b) }
    fun cstr(s: String) = apply { out.write(s.toByteArray(Charsets.UTF_8)); out.write(0) }
    fun uleb(v: Long): ByteBuilder {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x == 0L) { out.write(b); break } else out.write(b or 0x80)
        }
        return this
    }
    fun sleb(v: Long): ByteBuilder {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40 != 0
            x = x shr 7
            if ((x == 0L && !sign) || (x == -1L && sign)) { out.write(b); break } else out.write(b or 0x80)
        }
        return this
    }
    fun build(): ByteArray = out.toByteArray()
}

/**
 * 生成仅含调试信息所需最小结构的 ELF64 小端文件：
 * ELF 头、PT_LOAD 段、.shstrtab、.note.gnu.build-id 以及调用方提供的调试 section。
 * 这样测试无需任何系统工具链，输出可被本项目解析器完整消费。
 */
class ElfFixtureBuilder(
    private val machine: Int = 0x3e, // EM_X86_64
    private val loadVaddr: Long = 0x400000,
    private val buildId: ByteArray = ByteArray(8) { (0xa0 + it).toByte() }
) {
    private data class Sec(val name: String, val type: Long, val flags: Long, val addr: Long,
                           val bytes: ByteArray, val align: Long = 1L)

    private val sections = mutableListOf<Sec>()
    private val loadChunks = mutableListOf<Pair<Long, ByteArray>>() // vaddr offset -> bytes

    /** 加一段“代码”，决定 PT_LOAD 覆盖范围，供 load bias 演示。 */
    fun codeChunk(vaddr: Long, bytes: ByteArray) = apply { loadChunks += vaddr to bytes }

    fun debugSection(name: String, bytes: ByteArray) = apply {
        sections += Sec(name, 1L, 0L, 0L, bytes, 1L)
    }

    fun build(): ByteArray {
        // shstrtab
        val shstr = ByteBuilder().u8(0)
        val nameOff = LinkedHashMap<String, Int>()
        for (s in sections.map { it.name } + listOf(".shstrtab", ".note.gnu.build-id")) {
            if (s !in nameOff) { nameOff[s] = shstr.size; shstr.cstr(s) }
        }
        val shstrBytes = shstr.build()

        val noteName = "GNU\u0000".toByteArray(Charsets.US_ASCII)
        val note = ByteBuilder()
            .u32Int(noteName.size).u32Int(buildId.size).u32Int(3)
            .bytes(namePad(noteName))
            .bytes(buildId)
        if (buildId.size % 4 != 0) repeat(4 - buildId.size % 4) { note.u8(0) }
        val noteBytes = note.build()

        // 布局：ELF头 -> 程序头 -> 各 section 字节
        val ehdrSize = 64
        val phentsize = 56
        // PT_LOAD 覆盖所有代码 chunk
        var loadOff = 0L
        var loadVaddrStart = loadVaddr
        var loadFileSize = 0L
        if (loadChunks.isNotEmpty()) {
            val first = loadChunks.minBy { it.first }
            val last = loadChunks.maxBy { it.first + it.second.size }
            loadVaddrStart = first.first
            loadFileSize = last.first + last.second.size - first.first
        }
        var cursor = (ehdrSize + phentsize).toLong()
        data class Placed(val sec: Sec, val off: Long)
        val placed = mutableListOf<Placed>()
        fun alloc(b: ByteArray): Long { val o = cursor; cursor += b.size; return o }
        // note 先放
        val noteOff = alloc(noteBytes)
        val codePlacements = mutableMapOf<Long, Long>()
        for ((v, b) in loadChunks.sortedBy { it.first }) codePlacements[v] = alloc(b)
        loadOff = codePlacements[loadChunks.minByOrNull { it.first }?.first] ?: 0L
        for (s in sections) placed += Placed(s, alloc(s.bytes))
        val shstrOff = alloc(shstrBytes)

        val shentsize = 64
        val shnum = 1 + sections.size + 2 // NULL + debug + note + shstr
        val shoff = (cursor + 7) and 7.inv()
        cursor = shoff + shentsize * shnum

        val out = ByteArray(cursor.toInt())
        fun put16(at: Int, v: Int) { out[at] = (v and 0xff).toByte(); out[at+1] = ((v ushr 8) and 0xff).toByte() }
        fun put32(at: Int, v: Long) { repeat(4) { out[at+it] = ((v ushr (8*it)).toInt() and 0xff).toByte() } }
        fun put64(at: Int, v: Long) { repeat(8) { out[at+it] = ((v ushr (8*it)).toInt() and 0xff).toByte() } }
        // e_ident
        out[0] = 0x7f; out[1]='E'.code.toByte(); out[2]='L'.code.toByte(); out[3]='F'.code.toByte()
        out[4] = 2; out[5] = 1; out[6] = 1
        put16(16, 1) // ET_REL? 用 ET_EXEC=2 更贴合 load bias；用 ET_DYN=3 展示 PIE
        put16(18, machine)
        put64(24, loadVaddrStart)
        put64(32, phentsize.toLong()) // phoff
        put64(40, shoff)
        put16(52, 64)
        put16(54, phentsize)
        put16(56, if (loadChunks.isEmpty()) 0 else 1)
        put16(58, shentsize)
        put16(60, shnum)
        put16(62, shnum - 1)
        // 让文件为 PIE（bias 非零才有意义）
        put16(16, 3)

        // PT_LOAD
        if (loadChunks.isNotEmpty()) {
            val p = ehdrSize
            put32(p, 1) // PT_LOAD
            put32(p+4, 5) // PF_R|PF_X
            put64(p+8, loadOff)
            put64(p+16, loadVaddrStart)
            put64(p+24, loadVaddrStart)
            put64(p+32, loadFileSize)
            put64(p+40, loadFileSize)
            put64(p+48, 0x1000)
        }

        fun copyAt(off: Long, b: ByteArray) = System.arraycopy(b, 0, out, off.toInt(), b.size)
        copyAt(noteOff, noteBytes)
        for ((v, b) in loadChunks) copyAt(codePlacements[v]!!, b)
        for (pl in placed) copyAt(pl.off, pl.sec.bytes)
        copyAt(shstrOff, shstrBytes)

        fun shdr(idx: Int, name: String, type: Long, flags: Long, addr: Long, off: Long, size: Long,
                 link: Int = 0, align: Long = 1L) {
            val b = shoff.toInt() + idx * shentsize
            put32(b, (nameOff[name] ?: 0).toLong())
            put32(b+4, type)
            put64(b+8, flags)
            put64(b+16, addr)
            put64(b+24, off)
            put64(b+32, size)
            put32(b+40, link.toLong())
            put64(b+48, align)
        }
        var idx = 1
        for (pl in placed) {
            shdr(idx++, pl.sec.name, pl.sec.type, pl.sec.flags, pl.sec.addr, pl.off, pl.sec.bytes.size.toLong(), align = pl.sec.align)
        }
        shdr(idx++, ".note.gnu.build-id", 7L, 0L, 0L, noteOff, noteBytes.size.toLong())
        shdr(idx, ".shstrtab", 3L, 0L, 0L, shstrOff, shstrBytes.size.toLong())
        return out
    }

    private fun namePad(b: ByteArray): ByteArray {
        val n = (4 - b.size % 4) % 4
        return b + ByteArray(n)
    }
}
