package compass

import java.io.ByteArrayOutputStream

/**
 * Builds minimal but valid ELF64-LE files containing hand-crafted DWARF sections.
 * The goal is deterministic byte-level fixtures for special opcodes, end_sequence,
 * overlapping ranges, both high_pc meanings, DWARF 4/5, split dwarf and corruption.
 */
class FixtureBuilder(
    private val baseVaddr: Long = 0x400000,
    private val textBytes: ByteArray = ByteArray(0x100),
    private val textAddr: Long = baseVaddr
) {
    private val sections = LinkedHashMap<String, ByteArray>()
    var littleEndian = true

    fun section(name: String, data: ByteArray): FixtureBuilder { sections[name] = data; return this }

    fun debugInfo(d: ByteArray) = section(".debug_info", d)
    fun debugAbbrev(d: ByteArray) = section(".debug_abbrev", d)
    fun debugLine(d: ByteArray) = section(".debug_line", d)
    fun debugStr(d: ByteArray) = section(".debug_str", d)
    fun debugRanges(d: ByteArray) = section(".debug_ranges", d)
    fun debugRnglists(d: ByteArray) = section(".debug_rnglists", d)
    fun debugAddr(d: ByteArray) = section(".debug_addr", d)
    fun debugLineStr(d: ByteArray) = section(".debug_line_str", d)
    fun debugStrOffsets(d: ByteArray) = section(".debug_str_offsets", d)

    fun build(): ByteArray {
        // ELF64 header: 64 bytes, section header entry 64 bytes.
        val names = sections.keys.toList()
        val shstr = StringBuilder("\u0000").also { sb ->
            names.forEach { sb.append(it).append('\u0000') }
        }.toString().toByteArray()
        val fullNames = listOf("", *names.toTypedArray(), ".shstrtab")
        val nameOffsets = HashMap<String, Int>()
        var off = 1
        for (n in names) { nameOffsets[n] = off; off += n.length + 1 }
        val shstrOff = off

        // Layout: ELF header, one PT_LOAD program header, section headers, then section data.
        val ehdrSize = 64
        val phentsize = 56
        val phnum = 1
        val phoff = ehdrSize
        val shnum = fullNames.size
        val shentsize = 64
        val shoff = phoff + phnum * phentsize
        var cur = shoff + shnum * shentsize
        val dataOffsets = HashMap<String, Int>()
        for (n in names) {
            cur = (cur + 7) and 7.inv()
            dataOffsets[n] = cur
            cur += sections[n]!!.size
        }
        cur = (cur + 7) and 7.inv()
        val shstrFileOff = cur; cur += shstr.size
        // First and last file bytes covered by the LOAD segment.
        val loadStart = dataOffsets.values.minOrNull() ?: shstrFileOff
        val loadEnd = maxOf(shstrFileOff + shstr.size,
            dataOffsets.map { (it to sections.entries.first { e -> dataOffsets[e.key] == it.value }.key) }
                .maxOfOrNull { it.first + (sections[it.second]?.size ?: 0) } ?: 0)

        val out = ByteArray(cur)
        // ELF header
        out[0] = 0x7f; out[1]='E'.code.toByte(); out[2]='L'.code.toByte(); out[3]='F'.code.toByte()
        out[4] = 2; out[5] = if (littleEndian) 1 else 2; out[6] = 1
        put16(out, 16, 2)            // ET_EXEC
        put16(out, 18, 0x3e)         // x86-64
        put32(out, 20, 1)            // e_version
        put64(out, 24, baseVaddr)
        put64(out, 32, phoff.toLong())
        put64(out, 40, shoff.toLong())
        put16(out, 48, ehdrSize)
        put16(out, 52, phentsize)
        put16(out, 54, phnum)
        put16(out, 56, shentsize)
        put16(out, 58, shnum)
        put16(out, 60, fullNames.indexOf(".shstrtab"))
        put16(out, 62, 0)

        // PT_LOAD covers the file image; vaddr mapped to baseVaddr so load bias works.
        run {
            val ph = phoff
            put32(out, ph + 0, 1L)          // PT_LOAD
            put32(out, ph + 4, 5L)          // PF_R|PF_X
            put64(out, ph + 8, loadStart.toLong())
            put64(out, ph + 16, baseVaddr + loadStart)
            put64(out, ph + 24, baseVaddr + loadStart)
            put64(out, ph + 32, (loadEnd - loadStart).toLong())
            put64(out, ph + 40, (loadEnd - loadStart).toLong())
            put64(out, ph + 48, 0x1000)
        }
        // Section headers: index 0 null
        var idx = 1
        for (n in names) {
            val d = sections[n]!!
            val sh = shoff + idx * shentsize
            val addr = if (n == ".text") textAddr
                       else if (n.startsWith(".debug")) 0L
                       else 0L
            put32(out, sh + 0, nameOffsets[n]!!.toLong())
            put32(out, sh + 4, if (n == ".text") 1L else 0L)   // SHT_PROGBITS
            put64(out, sh + 8, if (n == ".text") 0x6L else 0L)  // ALLOC+EXEC for text
            put64(out, sh + 16, addr)
            put64(out, sh + 24, dataOffsets[n]!!.toLong())
            put64(out, sh + 32, d.size.toLong())
            put32(out, sh + 40, 0); put32(out, sh + 44, 0)
            put64(out, sh + 48, 1); put64(out, sh + 56, 0)
            System.arraycopy(d, 0, out, dataOffsets[n]!!, d.size)
            idx++
        }
        // shstrtab header
        run {
            val sh = shoff + idx * shentsize
            put32(out, sh + 0, shstrOff.toLong())
            put32(out, sh + 4, 3L) // SHT_STRTAB
            put64(out, sh + 24, shstrFileOff.toLong())
            put64(out, sh + 32, shstr.size.toLong())
            put64(out, sh + 48, 1)
            System.arraycopy(shstr, 0, out, shstrFileOff, shstr.size)
        }
        return out
    }

    private fun put16(d: ByteArray, o: Int, v: Int) {
        if (littleEndian) { d[o]=(v and 0xff).toByte(); d[o+1]=((v ushr 8) and 0xff).toByte() }
        else { d[o+1]=(v and 0xff).toByte(); d[o]=((v ushr 8) and 0xff).toByte() }
    }
    private fun put32(d: ByteArray, o: Int, v: Long) {
        for (i in 0 until 4) { val b = ((v ushr (8*i)) and 0xff).toLong(); d[o+i] = (if (littleEndian) b else ((v ushr (8*(3-i))) and 0xff)).toByte() }
    }
    private fun put64(d: ByteArray, o: Int, v: Long) {
        for (i in 0 until 8) { val b = (v ushr (8*i)) and 0xff; d[o+i] = (if (littleEndian) b else ((v ushr (8*(7-i))) and 0xff)).toByte() }
    }
}

class BinBuilder(private val le: Boolean = true) {
    private val out = ByteArrayOutputStream()
    val size get() = out.size()
    fun u8(v: Int): BinBuilder { out.write(v and 0xff); return this }
    fun u16(v: Int): BinBuilder {
        val b = ByteArray(2); for (i in 0 until 1) {}
        if (le) { b[0]=(v and 0xff).toByte(); b[1]=((v ushr 8) and 0xff).toByte() }
        else { b[1]=(v and 0xff).toByte(); b[0]=((v ushr 8) and 0xff).toByte() }
        out.write(b); return this
    }
    fun u32(v: Long): BinBuilder {
        val b = ByteArray(4)
        for (i in 0 until 4) b[if (le) i else 3-i] = ((v ushr (8*i)) and 0xff).toByte()
        out.write(b); return this
    }
    fun u64(v: Long): BinBuilder {
        val b = ByteArray(8)
        for (i in 0 until 8) b[if (le) i else 7-i] = (v ushr (8*i) and 0xff).toByte()
        out.write(b); return this
    }
    fun bytes(vararg v: Int): BinBuilder { v.forEach { out.write(it and 0xff) }; return this }
    fun blob(b: ByteArray): BinBuilder { out.write(b); return this }
    fun str(s: String): BinBuilder { out.write(s.toByteArray()); out.write(0); return this }
    fun uleb(v: Long): BinBuilder {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt(); x = x ushr 7
            if (x != 0L) out.write(b or 0x80) else { out.write(b); break }
        }
        return this
    }
    fun sleb(v: Long): BinBuilder {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40 != 0
            x = x shr 7
            if ((x == 0L && !sign) || (x == -1L && sign)) { out.write(b); break }
            else out.write(b or 0x80)
        }
        return this
    }
    fun build(): ByteArray = out.toByteArray()
}

/** DWARF length-prefixed unit (32-bit DWARF). */
fun dwarfUnit(body: BinBuilder.() -> Unit): ByteArray {
    val b = BinBuilder(); b.body()
    val payload = b.build()
    val hdr = BinBuilder().u32(payload.size.toLong()).build()
    return hdr + payload
}
