@file:Suppress("ArrayInDataClass")
package compass.fixture

import compass.fixture.DwarfFixture.FORM_ADDR
import compass.fixture.DwarfFixture.FORM_DATA1
import compass.fixture.DwarfFixture.FORM_DATA2
import compass.fixture.DwarfFixture.FORM_DATA4
import compass.fixture.DwarfFixture.FORM_DATA8
import compass.fixture.DwarfFixture.FORM_FLAG
import compass.fixture.DwarfFixture.FORM_FLAG_PRESENT
import compass.fixture.DwarfFixture.FORM_LINE_STRP
import compass.fixture.DwarfFixture.FORM_REF4
import compass.fixture.DwarfFixture.FORM_REF8
import compass.fixture.DwarfFixture.FORM_REF_ADDR
import compass.fixture.DwarfFixture.FORM_SEC_OFFSET
import compass.fixture.DwarfFixture.FORM_SDATA
import compass.fixture.DwarfFixture.FORM_STRP
import compass.fixture.DwarfFixture.FORM_STRING
import compass.fixture.DwarfFixture.FORM_STRX1
import compass.fixture.DwarfFixture.FORM_UDATA
import compass.fixture.DwarfFixture.FORM_ADDRX
import compass.fixture.DwarfFixture.FORM_RNGLISTX

data class CompiledUnit(val abbrev: ByteArray, val infoBody: ByteArray, val dieOffsets: Map<FixDie, Long>)

/**
 * Compiles a FixDie tree into a .debug_abbrev table plus a .debug_info DIE stream.
 * Abbreviation declarations are canonicalized (identical tag+attribute shapes share a code),
 * and codes are assigned in first-encounter order — deterministic for stable tests.
 */
fun compileUnit(root: FixDie): CompiledUnit {
    // 1) canonical abbreviations
    data class Sig(val tag: Int, val children: Boolean, val attrs: List<Pair<Int, Int>>)
    val sigToCode = LinkedHashMap<Sig, Long>()
    fun sigOf(d: FixDie): Sig =
        Sig(d.tag, d.children.isNotEmpty(), d.attrs.map { it.attr to it.form })
    fun codeFor(d: FixDie): Long = sigToCode.getOrPut(sigOf(d)) { (sigToCode.size + 1).toLong() }

    // 2) offset layout (depends only on forms + actual string lengths)
    val offsets = HashMap<FixDie, Long>()
    fun valueSize(a: FixAttr): Int = when (val v = a.value) {
        is FixForm.Addr -> 8
        is FixForm.Data1 -> 1
        is FixForm.Data2 -> 2
        is FixForm.Data4 -> 4
        is FixForm.Data8 -> 8
        is FixForm.UData -> Leb.uleb(v.v).size
        is FixForm.SData -> Leb.sleb(v.v).size
        is FixForm.Flag -> 1
        FixForm.FlagPresent -> 0
        is FixForm.Str -> v.v.toByteArray().size + 1
        is FixForm.Strp -> 4
        is FixForm.LineStrp -> 4
        is FixForm.SecOff -> 4
        is FixForm.Ref4 -> 4
        is FixForm.RefAddr -> 4
        is FixForm.Ref8 -> 8
        is FixForm.Addrx -> Leb.uleb(v.idx).size
        is FixForm.Rnglistx -> Leb.uleb(v.idx).size
        is FixForm.Strx1 -> 1
        is FixForm.Unknown -> v.consume
    }
    fun dieSize(d: FixDie): Int {
        var s = Leb.uleb(codeFor(d)).size
        for (a in d.attrs) s += valueSize(a)
        for (c in d.children) s += dieSize(c)
        if (d.children.isNotEmpty()) s += 1
        return s
    }
    var p = 0L
    fun layout(d: FixDie) {
        offsets[d] = p
        p += dieSize(d)
    }
    fun walkLayout(d: FixDie) { layout(d); d.children.forEach { walkLayout(it) } }
    walkLayout(root)

    // 3) emit abbrev bytes
    val ab = BytesBuilder()
    for ((sig, code) in sigToCode) {
        ab.uleb(code).uleb(sig.tag.toLong()).u8(if (sig.children) 1 else 0)
        for ((attr, form) in sig.attrs) ab.uleb(attr.toLong()).uleb(form.toLong())
        ab.uleb(0).uleb(0)
    }
    ab.uleb(0)

    // 4) emit info DIE bytes
    val info = BytesBuilder()
    fun emit(d: FixDie) {
        info.uleb(codeFor(d))
        for (a in d.attrs) info.bytes(DwarfFixture.encodeAttrValue(a))
        for (c in d.children) emit(c)
        if (d.children.isNotEmpty()) info.u8(0)
    }
    emit(root)
    return CompiledUnit(ab.build(), info.build(), offsets)
}

/** Builds the bytes that follow the 4-byte unit length for a DWARF <=4 CU. */
fun dwarf4CuHeader(abbrevOffset: Long = 0, addressSize: Int = 8, version: Int = 4): ByteArray =
    BytesBuilder().u16(version).u32(abbrevOffset).u8(addressSize).build()
