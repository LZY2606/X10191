package compass.fixtures

import java.io.ByteArrayOutputStream

/** LEB128 + little-endian primitives. */
class Bin {
    val out = ByteArrayOutputStream()
    fun u8(v: Int) = out.write(v and 0xff)
    fun u16(v: Int) { out.write(v and 0xff); out.write((v ushr 8) and 0xff) }
    fun u32(v: Long) { repeat(4) { out.write((v ushr (8 * it)).toInt()) } }
    fun u64(v: Long) { repeat(8) { out.write((v ushr (8 * it)).toInt()) } }
    fun s8(v: Int) = out.write(v) // signed byte via int low bits
    fun bytes(b: ByteArray) { out.write(b) }
    fun cstr(s: String) { out.write(s.toByteArray()); out.write(0) }
    fun uleb(v: Long) {
        var x = v
        do {
            var b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x != 0L) b = b or 0x80
            out.write(b)
        } while (x != 0L)
    }
    fun sleb(v: Long) {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40 != 0
            x = x shr 7
            if ((x == 0L && !sign) || (x == -1L && sign)) { out.write(b); break }
            else out.write(b or 0x80)
        }
    }
    fun bytes(): ByteArray = out.toByteArray()
}

/** One attribute spec used while emitting abbrev + info. */
data class AttrSpecF(val attr: Int, val form: Int, val implicit: Long? = null, val emit: (info: Bin) -> Unit)

class DwarfFixture(val version: Int = 4) {
    val abbrev = Bin()
    val info = Bin()
    val line = Bin()
    val ranges = Bin()
    val rnglists = Bin()
    val addr = Bin()
    val str = Bin()
    val lineStr = Bin()
    val strOffsets = Bin()

    private var nextAbbrev = 1L
    private var cuDwordLenPos = -1
    private var cuBodyStart = 0
    private var lineUnitLenPos = -1

    /** Begin a CU with given root attributes and children DIEs. */
    fun beginCu(
        rootAttrs: List<AttrSpecF>,
        children: List<DieF>,
        abbrevOffset: Long = 0,
        addressSize: Int = 8,
        unitType: Int = 0x01,
        typeSig: Long? = null,
    ) {
        val rootCode = nextAbbrev++
        emitAbbrev(rootCode, 0x11, true, rootAttrs)
        for (c in children) emitAbbrevForDie(c)
        abbrev.uleb(0) // end of abbrev table

        // CU header
        val body = Bin()
        body.u16(version)
        if (version >= 5) {
            body.u8(unitType); body.u8(addressSize); body.u32(abbrevOffset)
            if (unitType == 0x02 || unitType == 0x06) { body.u64(typeSig ?: 0); body.u32(0) }
        } else {
            body.u32(abbrevOffset); body.u8(addressSize)
        }
        // root DIE
        body.uleb(rootCode)
        rootAttrs.filter { it.implicit == null }.forEach { it.emit(body) }
        for (c in children) emitDie(body, c)
        body.u8(0) // end DIE tree

        info.u32(body.bytes().size.toLong())
        info.bytes(body.bytes())
    }

    private fun emitAbbrevForDie(die: DieF) {
        die.code = nextAbbrev++
        emitAbbrev(die.code, die.tag, die.children.isNotEmpty(), die.attrs)
        die.children.forEach { emitAbbrevForDie(it) }
    }

    private fun emitAbbrev(code: Long, tag: Int, hasChildren: Boolean, attrs: List<AttrSpecF>) {
        abbrev.uleb(code); abbrev.uleb(tag.toLong()); abbrev.u8(if (hasChildren) 1 else 0)
        for (a in attrs) {
            abbrev.uleb(a.attr.toLong()); abbrev.uleb(a.form.toLong())
            if (a.form == 0x21 /*implicit_const*/) abbrev.sleb(a.implicit ?: 0)
        }
        abbrev.uleb(0); abbrev.uleb(0)
    }

    private fun emitDie(b: Bin, die: DieF) {
        b.uleb(die.code)
        die.attrs.filter { it.implicit == null }.forEach { it.emit(b) }
        die.children.forEach { emitDie(b, it) }
        if (die.children.isNotEmpty()) b.u8(0)
    }

    fun die(tag: Int, attrs: List<AttrSpecF> = emptyList(), children: List<DieF> = emptyList()) =
        DieF(tag, attrs.toMutableList(), children.toMutableList(), -1)

    // ----- attribute form helpers -----
    fun name(s: String): AttrSpecF {
        val off = str.bytes().size
        str.cstr(s)
        return AttrSpecF(0x03 /*name*/, 0x0e /*strp*/) { it.u32(off.toLong()) }
    }
    fun strAttr(attr: Int, s: String, form: Int = 0x0e, lineStrSection: Boolean = false): AttrSpecF {
        val sec = if (lineStrSection) lineStr else str
        val off = sec.bytes().size
        sec.cstr(s)
        return AttrSpecF(attr, form) { it.u32(off.toLong()) }
    }
    fun lowPc(v: Long) = AttrSpecF(0x11, 0x01 /*addr*/) { it.u64(v) }
    fun highPcOffset(delta: Long) = AttrSpecF(0x12, 0x07 /*data8*/) { it.u64(delta) }
    fun highPcAddr(v: Long) = AttrSpecF(0x12, 0x01 /*addr*/) { it.u64(v) }
    fun stmtList(off: Long) = AttrSpecF(0x10, 0x17 /*sec_offset*/) { it.u32(off) }
    fun udataAttr(attr: Int, form: Int, value: Long) = AttrSpecF(attr, form) { b ->
        when (form) {
            0x0b -> b.u8(value.toInt())
            0x05 -> b.u16(value.toInt())
            0x06 -> b.u32(value)
            0x07 -> b.u64(value)
            0x0f -> b.uleb(value)
            else -> error("unsupported udata form $form")
        }
    }
    fun rangesSecOffset(off: Long) = AttrSpecF(0x55, 0x17) { it.u32(off) }
    fun rangesRnglistx(index: Long) = AttrSpecF(0x55, 0x23) { it.uleb(index) }
    fun attr(attr: Int, form: Int, implicit: Long? = null, emit: (Bin) -> Unit) = AttrSpecF(attr = attr, form = form, implicit = implicit, emit = emit)
    fun refAttr(attr: Int, form: Int, value: Long): AttrSpecF = when (form) {
        0x11 -> AttrSpecF(attr, form) { it.u8(value.toInt()) }
        0x12 -> AttrSpecF(attr, form) { it.u16(value.toInt()) }
        0x13 -> AttrSpecF(attr, form) { it.u32(value) }
        0x14 -> AttrSpecF(attr, form) { it.u64(value) }
        else -> AttrSpecF(attr, form) { it.uleb(value) }
    }

    // ----- line program -----
    private val LINE_BASE = -5

    fun beginLineV4(
        files: List<Triple<String, Int, String>>,
        dirs: List<String>,
        defaultStmt: Boolean = true,
    ): Int {
        val start = line.bytes().size
        // placeholder for unit length
        line.u32(0)
        val lenPos = line.bytes().size - 4
        line.u16(4)
        line.u8(1) // min insn length (no max_ops in DWARF 2/3/4)
        line.u8(if (defaultStmt) 1 else 0)
        line.s8(-5) // line_base
        line.u8(14) // line_range
        line.u8(13) // opcode_base
        // standard_opcode_lengths for opcodes 1..12:
        // 2 advance_pc=1, 3 line=1, 4 file=1, 5 set_column=1,
        // 10 set_prologue_end=0, 11 set_epilogue_begin=0, 12 set_isa=1
        listOf(0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1).forEach { line.u8(it) }
        dirs.forEach { line.cstr(it) }
        line.u8(0)
        files.forEach { (n, dirIdx, _) -> line.cstr(n); line.uleb(dirIdx.toLong()); line.uleb(0); line.uleb(0) }
        line.u8(0)
        lineLengthHolders += lenPos
        lineUnitStarts += start
        return lenPos
    }

    private val patchLen = HashMap<Int, Pair<Int, Int>>()
    private val lineLengthHolders = ArrayList<Int>()
    private val lineUnitStarts = ArrayList<Int>()

    fun specialOpcode(adjusted: Int) = 13 + adjusted
    fun emitRawSpecial(adjusted: Int) {
        val opcode = 13 + adjusted
        require(opcode in 13..255)
        line.u8(opcode)
    }
    fun emitSpecial(opAdvance: Int, lineIncrement: Int) {
        // Encode so that the state machine, which computes
        //   lineInc = (opcode-opcode_base) mod line_range + line_base
        // recovers exactly lineIncrement. Wrap into [line_base, line_base+range).
        val range = 14
        var wrapped = (lineIncrement - LINE_BASE) % range
        if (wrapped < 0) wrapped += range  // value already in 0 until range for +increments
        val adj = opAdvance * range + wrapped
        val opcode = 13 + adj
        require(opcode in 13..255) { "special opcode out of range: $opcode" }
        line.u8(opcode)
    }
    fun copy() = line.u8(1)
    fun advancePc(deltaUnits: Int) { line.u8(2); line.uleb(deltaUnits.toLong()) }
    fun setLine(l: Int) { line.u8(3); line.sleb(l.toLong()) }
    fun setFile(f: Int) { line.u8(4); line.uleb(f.toLong()) }
    fun setColumn(c: Int) { line.u8(5); line.uleb(c.toLong()) }
    fun endSequence(addr: Long) {
        line.u8(0)
        // DWARF: length includes the extended opcode byte (1) + address (8)
        line.uleb(9)
        line.u8(1)
        line.u64(addr)
    }
    fun setAddressExt(addr: Long) {
        line.u8(0)
        line.uleb(9)
        line.u8(2)
        line.u64(addr)
    }
    private var lineFinalized = false
    fun finalizeLine() {
        if (lineFinalized) return
        if (lineLengthHolders.isEmpty()) return
        patchOneLineLength()
        lineFinalized = true
    }

    // ----- DWARF 5 line program -----
    fun beginLineV5(
        dirs: List<String>,
        files: List<Pair<String, Int>>,
        defaultStmt: Boolean = true,
    ): Int {
        val start = line.bytes().size
        line.u32(0)
        val lenPos = line.bytes().size - 4
        val header = Bin()
        header.u16(5)
        header.u8(8) // address size
        header.u8(0) // segment selector
        val hlenPos = header.bytes().size
        header.u32(0) // header_length placeholder
        header.u8(1) // min insn
        header.u8(1) // max ops
        header.u8(if (defaultStmt) 1 else 0)
        header.s8(-5); header.u8(14); header.u8(13)
        repeat(12) { header.u8(0) }
        // directory entry formats: 1 entry: path, DW_FORM_line_strp (0x1f)
        header.u8(1); header.uleb(1); header.uleb(0x1f)
        // file name entry formats: path(line_strp), dir_index(data1)
        header.u8(2); header.uleb(1); header.uleb(0x1f); header.uleb(2); header.uleb(0x0b)
        val programStartPlaceholder = header.bytes().size
        // directories
        for (d in dirs) {
            val off = lineStr.bytes().size; lineStr.cstr(d)
            header.u8(1) // entry present; actually a non-zero byte is not required —
            // The directory entry has no count prefix; emit the form bytes directly.
        }
        // The above loop wrote a stray byte conceptually; rebuild cleanly instead.
        val clean = Bin()
        clean.u16(5); clean.u8(8); clean.u8(0); clean.u32(0)
        clean.u8(1); clean.u8(1); clean.u8(if (defaultStmt) 1 else 0)
        clean.s8(-5); clean.u8(14); clean.u8(13)
        listOf(0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1).forEach { clean.u8(it) }
        clean.u8(1); clean.uleb(1); clean.uleb(0x1f)
        clean.u8(2); clean.uleb(1); clean.uleb(0x1f); clean.uleb(2); clean.uleb(0x0b)
        val dirOffsets = dirs.map { val o = lineStr.bytes().size; lineStr.cstr(it); o.toLong() }
        for (o in dirOffsets) clean.u32(o)
        clean.u8(0) // end directories
        for ((name, dirIdx) in files) {
            val off = lineStr.bytes().size; lineStr.cstr(name)
            clean.u32(off.toLong()); clean.u8(dirIdx)
        }
        clean.u8(0) // end files
        val hlen = clean.bytes().size - 8
        for (i in 0 until 4) clean.out.toByteArray().let { }
        // patch header_length at offset 4 in clean
        val arr = clean.bytes().copyOf()
        for (i in 0 until 4) arr[4 + i] = ((hlen.toLong() ushr (8 * i)).toInt() and 0xff).toByte()
        line.bytes(arr)
        lineLengthHolders += lenPos
        lineUnitStarts += start
        return lenPos
    }

    private fun patchOneLineLength() {
        if (lineLengthHolders.isEmpty()) return
        val arr = line.bytes()
        for (i in lineUnitStarts.indices) {
            val unitStart = lineUnitStarts[i]
            val unitEnd = if (i + 1 < lineUnitStarts.size) lineUnitStarts[i + 1] else arr.size
            val len = (unitEnd - unitStart - 4).toLong()
            for (b in 0 until 4) arr[unitStart + b] = ((len ushr (8 * b)).toInt() and 0xff).toByte()
        }
        line.out.reset(); line.out.write(arr)
    }

    // ----- .debug_ranges v4 -----
    fun v4Range(baseAddressEntries: List<Pair<Long, Long>>, endWithNull: Boolean = true): Long {
        val off = ranges.bytes().size.toLong()
        for ((s, e) in baseAddressEntries) { ranges.u64(s); ranges.u64(e) }
        if (endWithNull) { ranges.u64(0); ranges.u64(0) }
        return off
    }
    fun v4RangeBaseAddress(base: Long) { ranges.u64(-1L); ranges.u64(base) }

    // ----- .debug_addr + rnglists v5 -----
    fun addrv5(entries: List<Long>): Long {
        val start = addr.bytes().size
        val body = Bin()
        entries.forEach { body.u64(it) }
        // 8-byte header (DWARF32): unit_length, version, addr_size, seg_size.
        addr.u32(4L + body.bytes().size.toLong()) // version+addr+seg = 4 bytes
        addr.u16(5); addr.u8(8); addr.u8(0)
        addr.bytes(body.bytes())
        // DW_AT_addr_base points just past the 8-byte header at the first entry.
        return (start + 8).toLong()
    }

    fun rnglistsV5(startxEndx: List<Pair<Int, Int>>? = null, absolute: Pair<Long, Long>? = null,
                   startxLen: Pair<Int, Long>? = null): Long {
        val start = rnglists.bytes().size
        val body = Bin()
        startxEndx?.forEach { (sx, ex) ->
            body.u8(0x02); body.uleb(sx.toLong()); body.uleb(ex.toLong())
        }
        startxLen?.let { (sx, len) -> body.u8(0x03); body.uleb(sx.toLong()); body.uleb(len) }
        absolute?.let { (sx, ex) -> body.u8(0x05); body.u64(sx); body.u64(ex) }
        body.u8(0x00) // DW_RLE_end_of_list
        val payload = body.bytes()
        // Header following unit_length: version(2) addr_size(1) seg(1)
        // offset_size(1) offset_entry_count(1) + 2 pad bytes = 8 bytes.
        rnglists.u32(8L + payload.size)
        rnglists.u16(5)
        rnglists.u8(8)
        rnglists.u8(0)
        rnglists.u8(4)
        rnglists.u8(0)
        rnglists.u16(0)
        rnglists.bytes(payload)
        return (start + 12).toLong()
    }
}

class DieF(
    val tag: Int,
    val attrs: MutableList<AttrSpecF>,
    val children: MutableList<DieF>,
    var code: Long,
)
