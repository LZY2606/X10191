package compass.fixture

import java.io.ByteArrayOutputStream

/** Minimal DWARF/ELF byte builder used by tests (little-endian ELF64). */
class Bin {
    val out = ByteArrayOutputStream()
    fun u8(v: Int) { out.write(v and 0xff) }
    fun u16(v: Int) { out.write(v and 0xff); out.write((v ushr 8) and 0xff) }
    fun u32(v: Long) {
        for (i in 0 until 4) out.write(((v ushr (8 * i)) and 0xff).toInt())
    }
    fun u64(v: Long) {
        for (i in 0 until 8) out.write(((v ushr (8 * i)) and 0xff).toInt())
    }
    fun bytes(b: ByteArray) { out.write(b) }
    fun cstr(s: String) { out.write(s.toByteArray()); out.write(0) }
    fun leb(v: Long) {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x == 0L) { out.write(b); break } else out.write(b or 0x80)
        }
    }
    fun uleb(v: Long) = leb(v)
    fun sleb(v: Long) {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40
            x = x shr 7
            if ((x == 0L && sign == 0) || (x == -1L && sign != 0)) { out.write(b); break }
            out.write(b or 0x80)
        }
    }
    val size get() = out.size()
    fun bytes(): ByteArray = out.toByteArray()
}

data class AbbrevSpec(val code: Int, val tag: Int, val children: Boolean, val attrs: List<Triple<Int, Int, Long?>>)

data class DieSpec(
    val tag: Int,
    val attrs: List<Pair<Int, Any>>, // attr -> value: Long / String / Pair("addr",Long)
    val children: List<DieSpec> = emptyList()
)

/** Builds .debug_abbrev for one table starting at offset 0. Returns (bytes, codes map). */
fun buildAbbrev(specs: List<AbbrevSpec>): ByteArray {
    val b = Bin()
    for (s in specs) {
        b.uleb(s.code.toLong())
        b.uleb(s.tag.toLong())
        b.u8(if (s.children) 1 else 0)
        for ((attr, form, implicit) in s.attrs) {
            b.uleb(attr.toLong()); b.uleb(form.toLong())
            if (form == 0x21 && implicit != null) b.sleb(implicit)
        }
        b.uleb(0); b.uleb(0)
    }
    b.uleb(0)
    return b.bytes()
}

/** DIE encoder; values keyed by form from the matching abbrev. */
fun encodeDies(b: Bin, dies: List<DieSpec>, abbrev: Map<Int, AbbrevSpec>) {
    fun encode(d: DieSpec, code: Int?) {
        val spec = abbrev[code] ?: error("no abbrev for code $code")
        for ((attr, form, _) in spec.attrs) {
            val v = d.attrs.first { it.first == attr }.second
            emitForm(b, form, v)
        }
        if (spec.children) {
            d.children.forEach { ch ->
                val childCode = abbrev.values.first { it.tag == ch.tag }.code
                b.uleb(childCode.toLong())
                encode(ch, childCode)
            }
            b.uleb(0)
        }
    }
    dies.forEach { root ->
        val code = abbrev.values.first { it.tag == root.tag }.code
        b.uleb(code.toLong())
        encode(root, code)
    }
}

fun emitForm(b: Bin, form: Int, v: Any) {
    val n = (v as? Number)?.toLong()
    when (form) {
        0x01 -> b.u64(n!!)                       // addr
        0x05 -> b.u16((n!!).toInt())             // data2
        0x06 -> b.u32(n!!)                       // data4
        0x07 -> b.u64(n!!)                       // data8
        0x0b -> b.u8((n!!).toInt())              // data1
        0x0c -> b.u8(if (v as Boolean) 1 else 0)       // flag
        0x0d -> b.sleb(n!!)                      // sdata
        0x0f -> b.uleb(n!!)                      // udata
        0x19 -> {}                                     // flag_present
        0x08 -> b.cstr(v as String)                    // string
        0x17 -> b.u32(n!!)                       // sec_offset
        0x10 -> b.u64(n!!)                       // ref_addr
        0x13 -> b.u32(n!!)                       // ref4
        0x0e -> b.u32(n!!)                       // strp
        0x1f -> b.u32(n!!)                       // line_strp
        else -> error("form 0x${form.toString(16)} not supported by fixture encoder")
    }
}

/** DWARF4 line program for a single CU with custom opcode stream builder. */
class LineProgBuilder(
    val minInsnLen: Int = 1,
    val defaultIsStmt: Int = 1,
    val lineBase: Int = -5,
    val lineRange: Int = 14,
    val opcodeBase: Int = 13
) {
    val op = Bin()
    fun special(advLine: Int, advPc: Int) {
        val adj = advLine - lineBase + opcodeBase + advPc * lineRange
        op.u8(adj)
    }
    fun std(code: Int, vararg operands: Long) { op.u8(code); operands.forEach { op.uleb(it) } }
    fun extSetAddr(addr: Long) {
        val body = Bin(); body.u8(2); body.u64(addr)
        op.u8(0); op.uleb(body.size.toLong()); op.bytes(body.bytes())
    }
    fun extEndSeq() {
        op.u8(0); op.uleb(1); op.u8(1)
    }
}

fun buildLineDwarf4(
    files: List<String>,
    dirs: List<String>,
    prog: LineProgBuilder,
    stdOpcodeLengths: IntArray = intArrayOf(0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1)
): ByteArray {
    val h = Bin()
    h.u8(prog.minInsnLen)
    h.u8(prog.defaultIsStmt)
    h.sleb(prog.lineBase.toLong())
    h.u8(prog.lineRange)
    h.u8(prog.opcodeBase)
    for (i in 1 until prog.opcodeBase) h.u8(stdOpcodeLengths.getOrElse(i) { 0 })
    dirs.forEach { h.cstr(it) }; h.cstr("")
    files.forEach { name ->
        // DWARF<=4 file entry: name, directory index (1-based into include table), time, size
        val dirIdx = if (dirs.isEmpty()) 0L else 1L
        h.cstr(name); h.uleb(dirIdx); h.uleb(0); h.uleb(0)
    }
    h.cstr("")
    val header = h.bytes()
    val ops = prog.op.bytes()
    val out = Bin()
    out.u32(2 + 4 + header.size.toLong() + ops.size.toLong())
    out.u16(4)
    out.u32(header.size.toLong())
    out.bytes(header)
    out.bytes(ops)
    return out.bytes()
}

/** DWARF5 line program: dirs/files via DW_LNCT_path/DW_FORM_line_strp into .debug_line_str. */
fun buildLineDwarf5(
    fileName: String,
    prog: LineProgBuilder,
    lineStr: ByteArray,
    lineStrIndex: Int
): ByteArray {
    val body = Bin()
    body.u8(prog.minInsnLen); body.u8(1)
    body.sleb(prog.lineBase.toLong()); body.u8(prog.lineRange); body.u8(prog.opcodeBase)
    for (i in 1 until prog.opcodeBase) body.u8(intArrayOf(0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1).getOrElse(i) { 0 })
    // directories: one, comp-dir path inline
    body.u8(1)
    body.uleb(1); body.uleb(0x08)
    body.uleb(1); body.cstr(".")
    // files: one, line_strp, dir index data1=0
    body.u8(2)
    body.uleb(1); body.uleb(0x1f)
    body.uleb(2); body.uleb(0x0b)
    body.uleb(1)
    body.u32(lineStrIndex.toLong()); body.u8(0)
    val headerOnly = body.bytes()
    val ops = prog.op.bytes()
    val out = Bin()
    out.u32(2 + 2 + 4 + headerOnly.size.toLong() + ops.size.toLong())
    out.u16(5); out.u8(8); out.u8(0)
    out.u32(headerOnly.size.toLong())
    out.bytes(headerOnly)
    out.bytes(ops)
    return out.bytes()
}

fun buildInfoDwarf4(
    abbrev: ByteArray,
    root: DieSpec,
    abbrevCodes: Map<Int, AbbrevSpec>,
    stmtOff: Long = 0
): ByteArray {
    val b = Bin()
    val attrs = root.attrs.toMutableList()
    if (attrs.none { it.first == 0x10 }) attrs.add(0x10 to stmtOff)
    val rootFixed = root.copy(attrs = attrs)
    encodeDies(b, listOf(rootFixed), abbrevCodes)
    val bodyLen = 2 + 4 + 1 + b.size
    val out = Bin()
    out.u32(bodyLen.toLong())
    out.u16(4)
    out.u32(0)
    out.u8(8)
    out.bytes(b.bytes())
    return out.bytes()
}

/**
 * Assemble a minimal ELF64 little-endian executable wrapping arbitrary named sections.
 * Section VMAs default to 0 for debug sections; assign via [vmas].
 */
fun buildElf(sections: Map<String, ByteArray>, vmas: Map<String, Long> = emptyMap()): ByteArray {
    val names = sections.keys.toList()
    val shstr = Bin()
    shstr.cstr("")
    val nameOff = HashMap<String, Int>()
    for (n in names) { nameOff[n] = shstr.size; shstr.cstr(n) }
    val shstrNameOff = shstr.size
    shstr.cstr(".shstrtab")
    val shstrBytes = shstr.bytes()

    // Layout: ELF header, section data (aligned), then shstrtab, then section headers.
    var cursor = 64
    val offsets = HashMap<String, Int>()
    val payloads = ArrayList<Pair<String, ByteArray>>()
    for (n in names) {
        val data = sections.getValue(n)
        offsets[n] = cursor
        payloads.add(n to data)
        cursor += data.size
    }
    val shstrOff = cursor
    cursor += shstrBytes.size
    cursor = (cursor + 7) and 7.inv()
    val shoff = cursor
    val shnum = names.size + 2 // null + sections + shstrtab
    val shentsize = 64

    val total = shoff + shnum * shentsize
    val raw = ByteArray(total)
    fun putU16(off: Int, v: Int) { raw[off] = (v and 0xff).toByte(); raw[off + 1] = ((v ushr 8) and 0xff).toByte() }
    fun putU32(off: Int, v: Long) { for (i in 0 until 4) raw[off + i] = ((v ushr (8 * i)) and 0xff).toByte() }
    fun putU64(off: Int, v: Long) { for (i in 0 until 8) raw[off + i] = ((v ushr (8 * i)) and 0xff).toByte() }

    raw[0] = 0x7f; raw[1] = 'E'.code.toByte(); raw[2] = 'L'.code.toByte(); raw[3] = 'F'.code.toByte()
    raw[4] = 2; raw[5] = 1; raw[6] = 1
    putU16(16, 2) // ET_EXEC
    putU16(18, 62)
    putU32(20, 1)
    putU64(24, 0x400000)
    putU64(32, 0) // phoff
    putU64(40, shoff.toLong())
    putU16(52, 64)
    putU16(54, 0) // phentsize
    putU16(56, 0) // phnum
    putU16(58, shentsize)
    putU16(60, shnum)
    putU16(62, names.size + 1)

    for ((n, data) in payloads) System.arraycopy(data, 0, raw, offsets.getValue(n), data.size)
    System.arraycopy(shstrBytes, 0, raw, shstrOff, shstrBytes.size)

    fun shdr(idx: Int, name: Int, type: Int, flags: Long, addr: Long, off: Int, size: Int, link: Int = 0, info: Int = 0) {
        val base = shoff + idx * shentsize
        putU32(base, name.toLong())
        putU32(base + 4, type.toLong())
        putU64(base + 8, flags)
        putU64(base + 16, addr)
        putU64(base + 24, off.toLong())
        putU64(base + 32, size.toLong())
        putU32(base + 40, link.toLong())
        putU32(base + 44, info.toLong())
        putU64(base + 48, 1)
    }
    names.forEachIndexed { i, n ->
        val data = sections.getValue(n)
        val isAlloc = n == ".text" || n == ".data"
        shdr(i + 1, nameOff.getValue(n), if (n.startsWith(".debug")) 1 else 1,
            if (isAlloc) 0x6L else 0L,
            vmas[n] ?: (if (isAlloc) 0x401000L else 0L),
            offsets.getValue(n), data.size)
    }
    shdr(names.size + 1, shstrNameOff, 3, 0, 0, shstrOff, shstrBytes.size)
    return raw
}
