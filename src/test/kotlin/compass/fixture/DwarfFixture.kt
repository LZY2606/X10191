@file:Suppress("ArrayInDataClass")
package compass.fixture

/**
 * Minimal DWARF section builder used by tests. Supports DWARF 4 and DWARF 5 constructs
 * required by the fixtures: custom abbrev tables, compile_unit / subprogram /
 * inlined_subroutine DIEs, low_pc+high_pc (both forms), ranges, v4 .debug_ranges and
 * v5 .debug_rnglists, .debug_addr, line programs with special/standard/extended opcodes.
 */

// ---- attribute model for fixtures ----
sealed interface FixForm {
    data class Addr(val v: Long) : FixForm
    data class Data1(val v: Int) : FixForm
    data class Data2(val v: Int) : FixForm
    data class Data4(val v: Long) : FixForm
    data class Data8(val v: Long) : FixForm
    data class UData(val v: Long) : FixForm
    data class SData(val v: Long) : FixForm
    data class Flag(val v: Boolean) : FixForm
    data object FlagPresent : FixForm
    data class Str(val v: String) : FixForm
    data class Strp(val offset: Long) : FixForm
    data class LineStrp(val offset: Long) : FixForm
    data class SecOff(val v: Long) : FixForm
    data class Ref4(val v: Long) : FixForm
    data class RefAddr(val v: Long) : FixForm
    data class Ref8(val v: Long) : FixForm
    data class Addrx(val idx: Long) : FixForm
    data class Rnglistx(val idx: Long) : FixForm
    data class Strx1(val idx: Int) : FixForm
    data class Unknown(val code: Int, val consume: Int = 0) : FixForm
}

data class FixAttr(val attr: Int, val form: Int, val value: FixForm, val implicit: Long? = null)
data class FixDie(val tag: Int, val children: List<FixDie> = emptyList(), val attrs: List<FixAttr> = emptyList()) {
    var offset: Long = -1
}

class AbbrevBuilder {
    class Decl(val code: Long, val tag: Int, val children: Boolean, val attrs: List<FixAttr>)
    private val decls = ArrayList<Decl>()
    private var nextCode = 1L
    fun decl(tag: Int, children: Boolean = false, block: AbbrevAttrScope.() -> Unit): Long {
        val scope = AbbrevAttrScope().apply(block)
        val code = nextCode++
        decls += Decl(code, tag, children, scope.attrs)
        return code
    }
    fun build(): ByteArray {
        val b = BytesBuilder()
        for (d in decls) {
            b.uleb(d.code).uleb(d.tag.toLong()).u8(if (d.children) 1 else 0)
            for (a in d.attrs) {
                b.uleb(a.attr.toLong()).uleb(a.form.toLong())
                if (a.form == 0x21 /* implicit_const */) b.sleb(a.implicit ?: 0)
            }
            b.uleb(0).uleb(0)
        }
        b.uleb(0)
        return b.build()
    }
}

class AbbrevAttrScope {
    val attrs = ArrayList<FixAttr>()
    fun at(attr: Int, form: Int, value: FixForm, implicit: Long? = null) {
        attrs += FixAttr(attr, form, value, implicit)
    }
}

object DwarfFixture {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED = 0x1d
    const val TAG_LEXICAL = 0x0b
    const val AT_NAME = 0x03
    const val AT_COMP_DIR = 0x1b
    const val AT_STMT_LIST = 0x10
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_RANGES = 0x55
    const val AT_CALL_FILE = 0x3b
    const val AT_CALL_LINE = 0x3a
    const val AT_DECL_FILE = 0x39
    const val AT_DECL_LINE = 0x3a
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_SPECIFICATION = 0x47
    const val AT_LINKAGE_NAME = 0x6e
    const val AT_INLINE = 0x20
    const val AT_STR_OFFSETS_BASE = 0x72
    const val AT_ADDR_BASE = 0x73
    const val AT_RNGLISTS_BASE = 0x74
    const val AT_DWO_ID = 0x75
    const val AT_DWO_NAME = 0x76

    const val FORM_ADDR = 0x01
    const val FORM_DATA1 = 0x0b
    const val FORM_DATA2 = 0x05
    const val FORM_DATA4 = 0x06
    const val FORM_DATA8 = 0x07
    const val FORM_UDATA = 0x0f
    const val FORM_SDATA = 0x0d
    const val FORM_FLAG = 0x0c
    const val FORM_FLAG_PRESENT = 0x19
    const val FORM_STRING = 0x08
    const val FORM_STRP = 0x0e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_SEC_OFFSET = 0x17
    const val FORM_REF4 = 0x13
    const val FORM_REF_ADDR = 0x10
    const val FORM_REF8 = 0x14
    const val FORM_ADDRX = 0x1b
    const val FORM_RNGLISTX = 0x23
    const val FORM_STRX1 = 0x26
    const val FORM_IMPLICIT_CONST = 0x21

    /** Encodes a DIE tree into .debug_info body content (no CU header). Assigns offsets. */
    fun encodeDies(root: FixDie, abbrevCodes: Map<Int, Long> = emptyMap(),
                   explicit: Map<FixDie, Long> = emptyMap()): ByteArray {
        val b = BytesBuilder()
        fun emit(die: FixDie, codeFor: (FixDie) -> Long) {
            die.offset = b.size.toLong()
            val code = explicit[die] ?: codeFor(die)
            b.uleb(code)
            for (a in die.attrs) b.bytes(encodeAttrValue(a))
            for (c in die.children) emit(c, codeFor)
            if (die.children.isNotEmpty()) b.u8(0)
        }
        // default: one abbrev per unique tag, in declaration order is handled by caller;
        // callers normally provide `explicit` codes; fallback assumes same code == tag mapping
        emit(root) { die ->
            abbrevCodes[die.tag] ?: error("no abbrev code for tag 0x${die.tag.toString(16)}")
        }
        return b.build()
    }

    fun encodeAttrValue(a: FixAttr): ByteArray {
        val b = BytesBuilder()
        when (val v = a.value) {
            is FixForm.Addr -> b.u64(v.v)
            is FixForm.Data1 -> b.u8(v.v)
            is FixForm.Data2 -> b.u16(v.v)
            is FixForm.Data4 -> b.u32(v.v)
            is FixForm.Data8 -> b.u64(v.v)
            is FixForm.UData -> b.uleb(v.v)
            is FixForm.SData -> b.sleb(v.v)
            is FixForm.Flag -> b.u8(if (v.v) 1 else 0)
            FixForm.FlagPresent -> {}
            is FixForm.Str -> b.str(v.v)
            is FixForm.Strp -> b.u32(v.offset)
            is FixForm.LineStrp -> b.u32(v.offset)
            is FixForm.SecOff -> b.u32(v.v)
            is FixForm.Ref4 -> b.u32(v.v)
            is FixForm.RefAddr -> b.u32(v.v)
            is FixForm.Ref8 -> b.u64(v.v)
            is FixForm.Addrx -> b.uleb(v.idx)
            is FixForm.Rnglistx -> b.uleb(v.idx)
            is FixForm.Strx1 -> b.u8(v.idx)
            is FixForm.Unknown -> repeat(v.consume) { b.u8(0) }
        }
        return b.build()
    }

    /** Assign DIE offsets without encoding (useful when building ref attrs). */
    fun layoutDies(root: FixDie, cuHeaderSize: Int, abbrevSizes: Map<FixDie, Int>): Map<FixDie, Long> {
        val offsets = HashMap<FixDie, Long>()
        var p = cuHeaderSize.toLong()
        fun walk(die: FixDie, depth: Int) {
            offsets[die] = p
            p += abbrevSizes[die] ?: error("missing abbrev size")
            for (c in die.children) walk(c, depth + 1)
            if (die.children.isNotEmpty()) p += 1
        }
        walk(root, 0)
        return offsets
    }
}

/** Encode a DIE tree using an explicit per-node abbreviation-code map. */
fun encodeDiesWithCodes(root: FixDie, codes: Map<FixDie, Long>): ByteArray {
    val b = BytesBuilder()
    fun emit(die: FixDie) {
        val code = codes[die] ?: error("no abbrev code supplied for DIE tag 0x${die.tag.toString(16)}")
        b.uleb(code)
        for (a in die.attrs) b.bytes(DwarfFixture.encodeAttrValue(a))
        for (c in die.children) emit(c)
        if (die.children.isNotEmpty()) b.u8(0)
    }
    emit(root)
    return b.build()
}
