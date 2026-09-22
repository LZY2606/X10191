package compass.dwarf

import compass.elf.ByteReader

/**
 * Parses .debug_info / .debug_info.dwo for one ELF file.
 *
 * Bounded everywhere: depth, DIE counts and reference hops are capped. An
 * unknown form aborts the containing CU (recording an issue) because its
 * length cannot be known, so continuing would desynchronise the cursor and
 * emit bogus DIEs.
 */
class InfoParser(
    private val ctx: ParseContext,
    private val fileId: Long,
    private val isDwoFile: Boolean
) {
    private val info: ByteReader = ctx.info
        ?: throw DwarfParseException("no .debug_info section")

    fun parse(): List<CompUnit> {
        val units = ArrayList<CompUnit>()
        var guard = 0
        while (!info.atEnd) {
            if (++guard > Limits.MAX_UNITS)
                throw DwarfParseException("more than ${Limits.MAX_UNITS} units")
            val unitStart = info.pos
            val unit = parseOneUnit(unitStart) ?: break
            units.add(unit)
            info.seek(unit.nextOffset.toInt())
        }
        return units
    }

    private fun parseOneUnit(unitStart: Int): CompUnit? {
        val (length, afterLen, dwarf64) = readInitialLength(info)
        if (length == 0L) return null
        val unitEnd = afterLen + length.toInt()
        val r = info.subReader(afterLen, length.toInt())
        val version = r.u2()
        var unitType = DW.TAG_compile_unit
        var debugAbbrevOffset: Long
        var addressSize: Int
        var dwoId: Long? = null
        var typeSig: Long? = null
        var typeOffset: Long? = null
        when {
            version >= 5 -> {
                unitType = r.u1()
                addressSize = r.u1()
                debugAbbrevOffset = r.readSectionOffset(dwarf64)
                if (unitType == DW.TAG_skeleton_unit || unitType == DW.TAG_split_compile_unit)
                    dwoId = r.u8()
                if (unitType == DW.TAG_type_unit) {
                    typeSig = r.u8()
                    typeOffset = r.readSectionOffset(dwarf64)
                }
            }
            version == 4 -> {
                debugAbbrevOffset = r.u4().toLong() and 0xffffffffL
                addressSize = r.u1()
            }
            else -> {
                debugAbbrevOffset = r.u4().toLong() and 0xffffffffL
                addressSize = r.u1()
            }
        }
        val issues = mutableListOf<ParseIssue>()
        val table = try {
            ctx.abbrevTable(debugAbbrevOffset)
        } catch (e: Exception) {
            issues.add(ParseIssue("error", "abbrev@$debugAbbrevOffset",
                "cannot read abbrev table: ${e.message}"))
            val stub = DieNode(afterLen.toLong(), 0, null)
            return CompUnit(fileId, isDwoFile, unitStart.toLong(), length.toLong(), version, unitType,
                addressSize, debugAbbrevOffset, unitEnd.toLong(), dwoId, typeSig, typeOffset,
                stub, issues)
        }
        val state = ParseState(fileId, isDwoFile, unitStart.toLong(), length.toLong(), version,
            unitType, addressSize, debugAbbrevOffset, unitEnd.toLong(), dwoId, typeSig, typeOffset,
            dwarf64, afterLen)
        var root: DieNode? = null
        try {
            root = parseDieTree(state, table, r)
        } catch (e: UnknownFormException) {
            state.issues.add(ParseIssue("error", "info+$unitStart",
                "unknown form 0x${e.form.toString(16)} at +${e.offset}: DIE tree truncated; " +
                    "line program and raw ranges remain usable"))
        } catch (e: Exception) {
            state.issues.add(ParseIssue("error", "info+$unitStart",
                "DIE parse stopped: ${e.message ?: e.javaClass.simpleName}"))
        }
        if (root == null) root = DieNode(afterLen.toLong(), 0, null)
        val unit = CompUnit(fileId, isDwoFile, unitStart.toLong(), length.toLong(), version, unitType,
            addressSize, debugAbbrevOffset, unitEnd.toLong(), dwoId, typeSig, typeOffset,
            root, state.issues, state.diesByOffset)
        root.num(DW.AT_str_offsets_base)?.let { unit.strOffsetsBase = it }
        root.num(DW.AT_addr_base)?.let { unit.addrBase = it }
        root.num(DW.AT_GNU_addr_base)?.let { unit.addrBase = it }
        root.num(DW.AT_rnglists_base)?.let { unit.rnglistsBase = it }
        return unit
    }

    private fun parseDieTree(state: ParseState, table: AbbrevTable, r: ByteReader): DieNode {
        var root: DieNode? = null
        val stack = ArrayDeque<DieNode>()
        var count = 0
        while (true) {
            val codeStart = r.save()
            val code = r.uleb()
            if (code == 0L) {
                if (stack.isNotEmpty()) stack.removeLast()
                if (stack.isEmpty()) {
                    if (r.atEnd) break
                    // root closed with trailing bytes: keep reading bounded until end
                    continue
                }
                continue
            }
            if (++count > Limits.MAX_DIES_PER_UNIT)
                throw DwarfParseException("more than ${Limits.MAX_DIES_PER_UNIT} DIEs in unit")
            val decl = table.decls[code]
                ?: throw DwarfParseException("abbrev code $code not present in table")
            val offsetInSection = state.unitStart + codeStart
            val parent = stack.lastOrNull()
            val die = DieNode(offsetInSection, decl.tag, parent)
            die.depth = stack.size
            for ((attr, form) in decl.specs) {
                val value = readForm(state, r, form, decl.implicitValues[attr])
                die.attributes[attr] = DieAttribute(attr, form, value)
            }
            state.diesByOffset[offsetInSection] = die
            if (root == null) {
                root = die
            } else {
                parent!!.children.add(die)
            }
            if (decl.hasChildren) {
                if (stack.size + 1 > Limits.MAX_DIE_DEPTH)
                    throw DwarfParseException("DIE depth exceeds ${Limits.MAX_DIE_DEPTH}")
                stack.addLast(die)
            }
        }
        return root ?: throw DwarfParseException("unit contains no DIE")
    }

    private fun readForm(state: ParseState, r: ByteReader, form: Int, implicit: Long?): FormValue =
        when (form) {
            DW.FORM_addr -> FormValue.Address(r.uword(state.addressSize))
            DW.FORM_data1 -> FormValue.Number(r.u1().toLong())
            DW.FORM_data2 -> FormValue.Number(r.u2().toLong())
            DW.FORM_data4 -> FormValue.Number(r.u4().toLong() and 0xffffffffL)
            DW.FORM_data8 -> FormValue.Number(r.u8())
            DW.FORM_sdata -> FormValue.Number(r.sleb(), signed = true)
            DW.FORM_udata -> FormValue.Number(r.uleb())
            DW.FORM_flag -> FormValue.Flag(r.u1() != 0)
            DW.FORM_flag_present -> FormValue.Flag(true)
            DW.FORM_implicit_const -> FormValue.Number(implicit ?: 0L, signed = true)
            DW.FORM_string -> FormValue.Text(r.cString())
            DW.FORM_strp -> FormValue.Text(ctx.readStr(r.readSectionOffset(state.dwarf64).toInt()))
            DW.FORM_line_strp ->
                FormValue.Text(ctx.readLineStr(r.readSectionOffset(state.dwarf64).toInt()))
            DW.FORM_block1 -> FormValue.Blob(r.bytes(r.u1()))
            DW.FORM_block2 -> FormValue.Blob(r.bytes(r.u2()))
            DW.FORM_block4 -> FormValue.Blob(r.bytes(r.u4()))
            DW.FORM_block -> FormValue.Blob(r.bytes(r.uleb().toInt()))
            DW.FORM_exprloc -> FormValue.Blob(r.bytes(r.uleb().toInt()))
            DW.FORM_sec_offset -> FormValue.SectionOffset(r.readSectionOffset(state.dwarf64))
            DW.FORM_ref1 -> FormValue.Reference(r.u1().toLong(), RefKind.LOCAL_INFO)
            DW.FORM_ref2 -> FormValue.Reference(r.u2().toLong() and 0xffffL, RefKind.LOCAL_INFO)
            DW.FORM_ref4 -> FormValue.Reference(r.u4().toLong() and 0xffffffffL, RefKind.LOCAL_INFO)
            DW.FORM_ref8 -> FormValue.Reference(r.u8(), RefKind.LOCAL_INFO)
            DW.FORM_ref_udata -> FormValue.Reference(r.uleb(), RefKind.LOCAL_INFO)
            DW.FORM_ref_addr ->
                FormValue.Reference(r.readSectionOffset(state.dwarf64), RefKind.GLOBAL_INFO)
            DW.FORM_ref_sig8 -> FormValue.Reference(r.u8(), RefKind.TYPE_SIGNATURE)
            DW.FORM_data16 -> FormValue.Blob(r.bytes(16))
            DW.FORM_strx, DW.FORM_strx1, DW.FORM_strx2, DW.FORM_strx3, DW.FORM_strx4 ->
                ctx.readStrx(state, readIndex(r, form))
            DW.FORM_addrx, DW.FORM_addrx1, DW.FORM_addrx2, DW.FORM_addrx3, DW.FORM_addrx4 ->
                ctx.readAddrx(state, readIndex(r, form))
            DW.FORM_rnglistx -> FormValue.SectionOffset(ctx.resolveRnglistx(state, r.uleb()))
            DW.FORM_indirect -> {
                val actual = r.uleb().toInt()
                if (actual == form) throw DwarfParseException("DW_FORM_indirect loop")
                readForm(state, r, actual, null)
            }
            GNU.FORM_GNU_addr_index -> ctx.readAddrx(state, r.uleb())
            GNU.FORM_GNU_str_index -> ctx.readStrx(state, r.uleb())
            GNU.FORM_GNU_rnglistx -> FormValue.SectionOffset(ctx.resolveRnglistx(state, r.uleb()))
            else -> throw UnknownFormException(form, r.save())
        }

    private fun readIndex(r: ByteReader, form: Int): Long = when (form) {
        DW.FORM_strx1, DW.FORM_addrx1 -> r.u1().toLong()
        DW.FORM_strx2, DW.FORM_addrx2 -> r.u2().toLong() and 0xffffL
        DW.FORM_strx3, DW.FORM_addrx3 -> r.u4().toLong() and 0xffffffL
        DW.FORM_strx4, DW.FORM_addrx4 -> r.u4().toLong() and 0xffffffffL
        else -> r.uleb()
    }
}

/** Mutable per-unit state used while the DIE tree is being read. */
class ParseState(
    val fileId: Long,
    val isDwoFile: Boolean,
    val unitStart: Long,
    val length: Long,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val unitEnd: Long,
    val dwoId: Long?,
    val typeSignature: Long?,
    val typeOffset: Long?,
    val dwarf64: Boolean,
    val headerLength: Int,
    val issues: MutableList<ParseIssue> = mutableListOf(),
    val diesByOffset: MutableMap<Long, DieNode> = LinkedHashMap(),
    var strOffsetsBase: Long = 0,
    var addrBase: Long = 0,
    var rnglistsBase: Long = 0
)

internal class UnknownFormException(val form: Int, val offset: Int) :
    RuntimeException("unknown form 0x${form.toString(16)}")

/** Reads DWARF initial length; returns (length, headerEndOffset, isDwarf64). */
fun readInitialLength(r: ByteReader): Triple<Long, Int, Boolean> {
    val start = r.pos
    val word = r.u4().toLong() and 0xffffffffL
    return if (word == 0xffffffffL) {
        Triple(r.u8(), start + 12, true)
    } else {
        Triple(word, start + 4, false)
    }
}

fun ByteReader.readSectionOffset(dwarf64: Boolean): Long =
    if (dwarf64) u8() else u4().toLong() and 0xffffffffL
