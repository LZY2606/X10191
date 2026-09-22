@file:Suppress("ArrayInDataClass")
package compass.fixture

import java.io.ByteArrayOutputStream

/** Mutable builder for one CU's DIE tree, used by tests/demo fixtures. */
class DieBuilder(var tag: Int) {
    var code: Int = 0
    val attrs = ArrayList<Triple<Int, Int, Any?>>() // attr, form, value
    val children = ArrayList<DieBuilder>()
    /** Section-global offset into .debug_info after assembly. */
    var offset: Long = -1

    fun attr(a: Int, form: Int, value: Any?) = also { attrs.add(Triple(a, form, value)) }
    fun child(b: DieBuilder) = also { children.add(b) }
    fun num(a: Int): Long? = attrs.firstOrNull { it.first == a }?.third as? Long
}

/** Emits minimal DWARF4/5 sections for hand-crafted fixture scenarios. */
class DwarfFixture(val version: Int = 5, val addressSize: Int = 8) {
    val strings = StringTable()
    val lineStrings = StringTable()
    val linePrograms = LinkedHashMap<Long, LineProgramBuilder>() // stmt_list offset -> builder

    val addrTable = ArrayList<Long>()
    val strOffsets = ArrayList<Long>()

    private val abbrevBytes = PBuf()
    private val infoBytes = PBuf()
    private var abbrevTableStart = 0
    private var nextCode = 1
    private val codeByShape = HashMap<String, Int>()
    private var abbrevWritten = false
    lateinit var root: DieBuilder
        private set

    fun rootDie(tag: Int, block: DieBuilder.() -> Unit = {}): DieBuilder {
        val d = DieBuilder(tag).apply(block)
        root = d
        emitUnit(d)
        return d
    }

    fun lineProgram(offset: Long, block: LineProgramBuilder.() -> Unit): LineProgramBuilder {
        val lp = LineProgramBuilder(this).apply(block)
        linePrograms[offset] = lp
        return lp
    }

    fun addAddr(v: Long): Long { val i = addrTable.size.toLong(); addrTable.add(v); return i }
    fun addString(s: String): Long {
        val off = strings.put(s)
        val i = strOffsets.size.toLong(); strOffsets.add(off); return i
    }

    private fun shapeKey(d: DieBuilder): String =
        d.tag.toString() + "|" + d.attrs.joinToString(",") { "${it.first}:${it.second}" }

    private fun assignCodes(d: DieBuilder) {
        d.code = codeByShape.getOrPut(shapeKey(d)) { nextCode++ }
        d.children.forEach { assignCodes(it) }
    }

    private fun emitUnit(root: DieBuilder) {
        assignCodes(root)
        if (!abbrevWritten) {
            abbrevTableStart = 0
            val emitted = HashSet<Int>()
            fun emitAbbrev(d: DieBuilder) {
                if (emitted.add(d.code)) {
                    writeUleb(abbrevBytes, d.code.toLong())
                    writeUleb(abbrevBytes, d.tag.toLong())
                    abbrevBytes.write(if (d.children.isNotEmpty()) 1 else 0)
                    for ((a, f, v) in d.attrs) {
                        writeUleb(abbrevBytes, a.toLong())
                        writeUleb(abbrevBytes, f.toLong())
                        if (f == F_implicit_const) writeSleb(abbrevBytes, (v as Number).toLong())
                    }
                    writeUleb(abbrevBytes, 0); writeUleb(abbrevBytes, 0)
                    d.children.forEach { emitAbbrev(it) }
                }
            }
            emitAbbrev(root)
            writeUleb(abbrevBytes, 0)
            abbrevWritten = true
        }

        val body = ByteArrayOutputStream()
        writeU16(body, version.toLong())
        val dwoId = root.num(AT_dwo_id)
        val isSkeleton = root.attrs.any { it.first == AT_dwo_name || it.first == AT_GNU_dwo_name }
        val unitType = when {
            dwoId != null && isSkeleton -> DW_UT_skeleton
            dwoId != null -> DW_UT_split
            else -> DW_UT_compile
        }
        if (version >= 5) {
            body.write(unitType)
            body.write(addressSize)
            writeU32(body, abbrevTableStart.toLong())
            if (unitType == DW_UT_skeleton || unitType == DW_UT_split) writeU64(body, dwoId!!)
        } else {
            writeU32(body, abbrevTableStart.toLong())
            body.write(addressSize)
        }

        val unitLengthPos = infoBytes.size()
        // placeholder initial length + header; fill after DIEs to know offsets
        writeU32(infoBytes, 0)
        val unitStart = infoBytes.size()
        infoBytes.write(body.toByteArray())
        fun emitDie(d: DieBuilder) {
            d.offset = infoBytes.size().toLong()
            writeUleb(infoBytes, d.code.toLong())
            for ((_, f, v) in d.attrs) writeForm(f, v)
            d.children.forEach { emitDie(it) }
            if (d.children.isNotEmpty()) writeUleb(infoBytes, 0)
        }
        emitDie(root)
        writeUleb(infoBytes, 0)
        val unitEnd = infoBytes.size()
        val len = unitEnd - unitStart
        infoBytes.buf[unitLengthPos] = (len and 0xff).toByte()
        infoBytes.buf[unitLengthPos + 1] = ((len ushr 8) and 0xff).toByte()
        infoBytes.buf[unitLengthPos + 2] = ((len ushr 16) and 0xff).toByte()
        infoBytes.buf[unitLengthPos + 3] = ((len ushr 24) and 0xff).toByte()
    }

    private fun writeForm(form: Int, value: Any?) {
        when (form) {
            F_addr -> writeAddr(value as Long)
            F_data1 -> infoBytes.write((value as Number).toInt())
            F_data2 -> writeU16(infoBytes, (value as Number).toLong())
            F_data4 -> writeU32(infoBytes, (value as Number).toLong())
            F_data8 -> writeU64(infoBytes, (value as Number).toLong())
            F_sdata -> writeSleb(infoBytes, (value as Number).toLong())
            F_udata -> writeUleb(infoBytes, (value as Number).toLong())
            F_flag -> infoBytes.write(if (value as Boolean) 1 else 0)
            F_flag_present -> {}
            F_implicit_const -> {}
            F_string -> { infoBytes.write((value as String).toByteArray()); infoBytes.write(0) }
            F_strp -> writeAddr(strings.put(value as String))
            F_sec_offset -> writeAddr((value as Number).toLong())
            F_ref_addr -> writeAddr((value as Number).toLong())
            F_ref1 -> {
                val target = if (value is DieBuilder) (value.offset - root.offset) else (value as Number).toLong()
                infoBytes.write(target.toInt())
            }
            F_ref4 -> {
                val target = if (value is DieBuilder) (value.offset - root.offset) else (value as Number).toLong()
                writeU32(infoBytes, target)
            }
            F_strx, F_addrx, F_rnglistx, F_GNU_addr_index, F_GNU_str_index, F_GNU_rnglistx ->
                writeUleb(infoBytes, (value as Number).toLong())
            F_strx1, F_addrx1 -> infoBytes.write((value as Number).toInt())
            F_strx2, F_addrx2 -> writeU16(infoBytes, (value as Number).toLong())
            F_strx4, F_addrx4 -> writeU32(infoBytes, (value as Number).toLong())
            F_data16 -> repeat(16) { infoBytes.write(0) }
            else -> throw IllegalArgumentException("fixture: form 0x${form.toString(16)} unsupported")
        }
    }

    /** Raw .debug_info bytes (tests can inspect/patch). */
    fun infoBlob(): ByteArray = infoBytes.toByteArray()

    private fun writeAddr(v: Long) {
        if (addressSize == 8) writeU64(infoBytes, v) else writeU32(infoBytes, v)
    }

    fun assembleSections(
        rangesBytes: ByteArray? = null,
        rnglistsBytes: ByteArray? = null,
        dwoSuffix: Boolean = false,
        includeLine: Boolean = true
    ): List<ElfWriter.Section> {
        val list = ArrayList<ElfWriter.Section>()
        fun n(base: String) = if (dwoSuffix) "$base.dwo" else base
        list.add(ElfWriter.Section(n(".debug_abbrev"), abbrevBytes.toByteArray()))
        list.add(ElfWriter.Section(n(".debug_info"), infoBytes.toByteArray()))
        if (strings.bytes.size() > 1)
            list.add(ElfWriter.Section(n(".debug_str"), strings.bytes.toByteArray()))
        if (lineStrings.bytes.size() > 1)
            list.add(ElfWriter.Section(n(".debug_line_str"), lineStrings.bytes.toByteArray()))
        if (addrTable.isNotEmpty()) {
            val a = ByteArrayOutputStream()
            writeU32(a, 12L + addrTable.size.toLong() * addressSize)
            writeU16(a, 5); a.write(addressSize); a.write(0); a.write(0)
            for (v in addrTable) if (addressSize == 8) writeU64(a, v) else writeU32(a, v)
            list.add(ElfWriter.Section(n(".debug_addr"), a.toByteArray()))
        }
        if (strOffsets.isNotEmpty()) {
            val b = ByteArrayOutputStream()
            val content = ByteArrayOutputStream()
            writeU16(content, 5); content.write(addressSize); content.write(0); content.write(0)
            for (off in strOffsets) if (addressSize == 8) writeU64(content, off) else writeU32(content, off)
            writeU32(b, content.size().toLong())
            b.write(content.toByteArray())
            list.add(ElfWriter.Section(n(".debug_str_offsets"), b.toByteArray()))
        }
        rangesBytes?.let { list.add(ElfWriter.Section(n(".debug_ranges"), it)) }
        rnglistsBytes?.let { list.add(ElfWriter.Section(n(".debug_rnglists"), it)) }
        if (includeLine && linePrograms.isNotEmpty()) {
            // Concatenate programs at their stmt_list offsets (contiguous in fixtures).
            val expectedOffsets = linePrograms.keys.sorted()
            val merged = ByteArrayOutputStream()
            for (off in expectedOffsets) {
                val blob = linePrograms.getValue(off).build(version, addressSize)
                if (merged.size() < off) {
                    repeat((off - merged.size()).toInt()) { merged.write(0) }
                }
                merged.write(blob)
            }
            list.add(ElfWriter.Section(n(".debug_line"), merged.toByteArray()))
        }
        return list
    }

    companion object {
        // attribute constants
        const val AT_name = 0x03
        const val AT_stmt_list = 0x10
        const val AT_low_pc = 0x11
        const val AT_high_pc = 0x12
        const val AT_ranges = 0x55
        const val AT_rnglists = 0x63
        const val AT_str_offsets_base = 0x72
        const val AT_addr_base = 0x73
        const val AT_rnglists_base = 0x74
        const val AT_dwo_name = 0x76
        const val AT_dwo_id = 0x2015
        const val AT_GNU_dwo_name = 0x2130
        const val AT_GNU_dwo_id = 0x2131
        const val AT_GNU_addr_base = 0x2133
        const val AT_abstract_origin = 0x31
        const val AT_call_file = 0x58
        const val AT_call_line = 0x59
        const val AT_call_column = 0x57
        const val AT_inline = 0x20

        const val TAG_compile_unit = 0x11
        const val TAG_subprogram = 0x2e
        const val TAG_inlined_subroutine = 0x1d
        const val TAG_skeleton_unit = 0x4a
        const val TAG_split_compile_unit = 0x41

        const val DW_UT_compile = 0x01
        const val DW_UT_skeleton = 0x04
        const val DW_UT_split = 0x05

        // forms
        const val F_addr = 0x01
        const val F_data1 = 0x0b
        const val F_data2 = 0x05
        const val F_data4 = 0x06
        const val F_data8 = 0x07
        const val F_sdata = 0x0d
        const val F_udata = 0x0f
        const val F_string = 0x08
        const val F_strp = 0x0e
        const val F_flag = 0x0c
        const val F_flag_present = 0x19
        const val F_implicit_const = 0x21
        const val F_sec_offset = 0x17
        const val F_ref_addr = 0x10
        const val F_ref1 = 0x11
        const val F_ref4 = 0x13
        const val F_strx = 0x1a
        const val F_strx1 = 0x1a
        const val F_strx2 = 0x1b
        const val F_strx4 = 0x1d
        const val F_addrx = 0x1f
        const val F_addrx1 = 0x1f
        const val F_addrx2 = 0x20
        const val F_addrx4 = 0x22
        const val F_rnglistx = 0x23
        const val F_GNU_addr_index = 0x1f01
        const val F_GNU_str_index = 0x1f02
        const val F_GNU_rnglistx = 0x1f23
        const val F_data16 = 0x25

        fun writeUleb(out: ByteArrayOutputStream, vIn: Long) {
            var v = vIn
            do {
                var b = (v and 0x7f).toInt()
                v = v ushr 7
                if (v != 0L) b = b or 0x80
                out.write(b)
            } while (v != 0L)
        }
        fun writeSleb(out: ByteArrayOutputStream, vIn: Long) {
            var v = vIn
            while (true) {
                val b = (v and 0x7f).toInt()
                val sign = b and 0x40
                v = v shr 7
                if ((v == 0L && sign == 0) || (v == -1L && sign != 0)) { out.write(b); return }
                out.write(b or 0x80)
            }
        }
        fun writeU16(out: ByteArrayOutputStream, v: Long) {
            out.write((v and 0xff).toInt()); out.write(((v ushr 8) and 0xff).toInt())
        }
        fun writeU32(out: ByteArrayOutputStream, v: Long) {
            for (i in 0..3) out.write(((v ushr (8 * i)) and 0xff).toInt())
        }
        fun writeU64(out: ByteArrayOutputStream, v: Long) {
            for (i in 0..7) out.write(((v ushr (8 * i)) and 0xff).toInt())
        }
    }
}

class StringTable {
    val bytes = ByteArrayOutputStream().apply { write(0) }
    private val offsets = HashMap<String, Long>()
    fun put(s: String): Long = offsets.getOrPut(s) {
        val off = bytes.size().toLong()
        bytes.write(s.toByteArray()); bytes.write(0); off
    }
}
