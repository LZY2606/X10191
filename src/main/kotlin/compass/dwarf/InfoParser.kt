package compass.dwarf

import compass.dwarf.DW.AT_GNU_addr_base
import compass.dwarf.DW.AT_GNU_dwo_id
import compass.dwarf.DW.AT_GNU_dwo_name
import compass.dwarf.DW.AT_GNU_str_offsets_base
import compass.dwarf.DW.AT_addr_base
import compass.dwarf.DW.AT_comp_dir
import compass.dwarf.DW.AT_dwo_id
import compass.dwarf.DW.AT_dwo_name
import compass.dwarf.DW.AT_language
import compass.dwarf.DW.AT_name
import compass.dwarf.DW.AT_rnglists_base
import compass.dwarf.DW.AT_segment
import compass.dwarf.DW.AT_str_offsets_base
import compass.dwarf.DW.UT_SKELETON
import compass.dwarf.DW.UT_SPLIT_COMPILE
import compass.dwarf.DW.UT_SPLIT_TYPE
import compass.dwarf.DW.UT_TYPE
import compass.model.AttrForm
import compass.model.AttrValue
import compass.model.Attribute
import compass.model.BoundsException
import compass.model.BoundedReader
import compass.model.CompilationUnit
import compass.model.Die
import compass.model.ParseIssue
import java.nio.ByteOrder

const val MAX_INDIRECTIONS = 16
const val MAX_FORM_BLOCK = 1 shl 24

class UnknownFormException(val formCode: Int) : RuntimeException("unknown form 0x${formCode.toString(16)}")

/**
 * Parses .debug_info. Every CU is read inside a hard BoundedReader window equal
 * to the declared unit_length. An unknown form aborts the whole CU at the point
 * encountered (rather than guessing a skip width), so later CUs are still
 * reached from their independent headers and no desync artifacts are produced.
 */
class InfoParser(private val sections: DebugSections) {
    private val order: ByteOrder = if (sections.elf.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
    private val issues = ArrayList<ParseIssue>()
    val issuesView: List<ParseIssue> get() = issues

    fun parse(): List<CompilationUnit> {
        val info = sections.info ?: return emptyList()
        val abbrev = sections.abbrev
        val units = ArrayList<CompilationUnit>()
        var cursor = 0
        while (cursor < info.size) {
            val start = cursor
            try {
                if (abbrev == null) throw BoundsException("missing .debug_abbrev")
                val (cu, next) = parseUnit(info, abbrev, cursor)
                if (next <= cursor) throw BoundsException("CU @$cursor did not advance")
                units += cu
                cursor = next
            } catch (e: BoundsException) {
                issues += ParseIssue("ERROR", "INFO_TRUNCATED",
                    "CU @$start abandoned: ${e.message}", ".debug_info", start.toLong())
                break
            } catch (e: UnknownFormException) {
                issues += ParseIssue("ERROR", "UNKNOWN_FORM",
                    "CU @$start abandoned at ${DwarfNames.form(e.formCode)}; subsequent DIEs in this CU are not guessed, remaining CUs parsed from their own headers",
                    ".debug_info", start.toLong())
                break
            } catch (e: Exception) {
                issues += ParseIssue("ERROR", "INFO_BAD",
                    "CU @$start abandoned: ${e.javaClass.simpleName}: ${e.message}", ".debug_info", start.toLong())
                break
            }
        }
        return units
    }

    private data class Header(
        val version: Int, val unitType: Int, val is64: Boolean, val addressSize: Int,
        val abbrevOffset: Long, val firstDie: Int, val unitEnd: Int,
        val dwoId: Long?, val typeSig: Long?,
    )

    private fun parseUnit(info: ByteArray, abbrev: ByteArray, offset: Int): Pair<CompilationUnit, Int> {
        val r = BoundedReader(info, 0, info.size, order)
        r.seek(offset)
        val lengthField = r.u32()
        val is64: Boolean
        val unitLength: Long
        if (lengthField == 0xffffffffL) {
            is64 = true
            unitLength = r.u64()
        } else {
            is64 = false
            unitLength = lengthField
        }
        val unitEnd = Math.addExact(r.pos, unitLength.toInt())
        if (unitLength < 4 || unitEnd > info.size) throw BoundsException("CU at $offset length $unitLength overruns section")
        r.limit = unitEnd

        val version = r.u16()
        if (version !in 2..5) throw BoundsException("unsupported DWARF version $version")

        var unitType = 0
        var addressSize = sections.elf.elfClass.bytes
        var abbrevOffset = 0L
        var dwoId: Long? = null
        var typeSig: Long? = null

        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOffset = r.readOffset(is64)
            if (unitType == UT_TYPE || unitType == UT_SPLIT_TYPE) {
                typeSig = r.u64()
                r.readOffset(is64) // type offset
            }
            if (unitType == UT_SKELETON) dwoId = r.u64()
        } else {
            abbrevOffset = r.readOffset(is64)
            addressSize = r.u8()
            r.u8() // segment selector size
        }
        val firstDie = r.pos

        val table = AbbrevParser.parseTable(abbrev, abbrevOffset, sections.elf.littleEndian)
        val dies = LinkedHashMap<Long, Die>()
        var root: Die? = null

        val openChain = ArrayDeque<Die>()
        var depth = 0
        while (r.pos < unitEnd) {
            val dieStart = r.pos
            val code = r.uleb()
            if (code == 0L) {
                depth--
                if (openChain.isNotEmpty()) openChain.removeLast()
                if (depth < 0) {
                    // stray null byte; resync by ending this CU
                    break
                }
                continue
            }
            val decl = table.get(code) ?: throw BoundsException("abbrev code $code missing in table @$abbrevOffset")
            val attrs = ArrayList<Attribute>(decl.specs.size)
            for ((attrName, formCode) in decl.specs) {
                val value = readForm(r, formCode, version, is64, addressSize, 0)
                attrs += Attribute(attrName, formCode, value)
            }
            val die = Die(dieStart.toLong(), decl.tag, depth, attrs)
            if (depth == 0) root = die
            if (openChain.isNotEmpty()) {
                val parent = openChain.last()
                die.parentOffset = parent.offset
                parent.childrenOffsets += die.offset
            }
            dies[dieStart.toLong()] = die
            if (decl.hasChildren) {
                depth++
                openChain.addLast(die)
            }
        }

        val rootDie = root
        val rngBase = rootDie?.num(AT_rnglists_base) ?: rootDie?.num(0x2133) ?: 0L
        val strOffBase = rootDie?.num(AT_str_offsets_base) ?: rootDie?.num(AT_GNU_str_offsets_base) ?: 0L
        val aBase = rootDie?.num(AT_addr_base) ?: rootDie?.num(AT_GNU_addr_base) ?: 0L
        val legacyDwoId = rootDie?.num(AT_GNU_dwo_id) ?: rootDie?.num(AT_dwo_id)
        if (dwoId == null) dwoId = legacyDwoId

        val name = rootDie?.str(AT_name)
        val compDir = rootDie?.str(AT_comp_dir)
        val dwoName = rootDie?.str(AT_dwo_name) ?: rootDie?.str(AT_GNU_dwo_name)
        val language = rootDie?.num(AT_language)?.toInt()
        val isSkeleton = unitType == UT_SKELETON || (version < 5 && dwoId != null && dwoName != null)
        val isSplit = unitType == UT_SPLIT_COMPILE || unitType == UT_SPLIT_TYPE
        val selector = rootDie?.num(AT_segment) ?: 0L

        val cu = CompilationUnit(
            version = version, unitType = unitType, is64Bit = is64,
            headerOffset = offset.toLong(), abbrevOffset = abbrevOffset,
            addressSize = addressSize, segmentSize = selector.toInt(),
            firstDieOffset = firstDie.toLong(), nextUnitOffset = unitEnd.toLong(),
            name = name, compDir = compDir, dies = dies, root = rootDie,
            dwoId = dwoId, dwoName = dwoName,
            isSkeleton = isSkeleton, isSplit = isSplit,
            rangeLists = emptyList(), rnglistsBase = rngBase,
            strOffsetsBase = strOffBase, addrBase = aBase,
            sourceLanguage = language,
        )
        return cu to unitEnd
    }

    private fun readForm(
        r: BoundedReader, formCodeRaw: Int, version: Int, is64: Boolean, addressSize: Int,
        indirections: Int,
    ): AttrValue {
        if (indirections > MAX_INDIRECTIONS) throw BoundsException("DW_FORM_indirect chain exceeds $MAX_INDIRECTIONS")
        var formCode = formCodeRaw
        var indirectionDepth = indirections
        if (formCode == AttrForm.INDIRECT.code) {
            formCode = r.uleb().toInt()
            indirectionDepth++
        }
        val form = AttrForm.from(formCode) ?: throw UnknownFormException(formCode)
        return when (form) {
            AttrForm.INDIRECT -> readForm(r, formCode, version, is64, addressSize, indirectionDepth + 1)
            AttrForm.ADDR -> AttrValue.Addr(r.uint(addressSize))
            AttrForm.DATA1, AttrForm.REF1, AttrForm.STRX1, AttrForm.ADDRX1 -> AttrValue.Num(r.u8().toLong())
            AttrForm.DATA2, AttrForm.REF2, AttrForm.STRX2, AttrForm.ADDRX2 -> AttrValue.Num(r.u16().toLong())
            AttrForm.DATA4, AttrForm.REF4, AttrForm.REF_SUP4, AttrForm.STRX4, AttrForm.ADDRX4 -> AttrValue.Num(r.u32())
            AttrForm.DATA8, AttrForm.REF8, AttrForm.REF_SUP8 -> AttrValue.Num(r.u64())
            AttrForm.REF_SIG8 -> AttrValue.Sig8(r.u64())
            AttrForm.UDATA, AttrForm.REF_UDATA -> AttrValue.Num(r.uleb())
            AttrForm.SDATA -> AttrValue.Num(r.sleb())
            AttrForm.FLAG -> AttrValue.Bool(r.u8() != 0)
            AttrForm.FLAG_PRESENT -> AttrValue.Bool(true)
            AttrForm.STRING -> AttrValue.Str(r.nulString())
            AttrForm.STRP -> readStrp(r, is64, sections.str, ".debug_str")
            AttrForm.LINE_STRP -> readStrp(r, is64, sections.lineStr, ".debug_line_str")
            AttrForm.STRP_SUP -> { r.readOffset(is64); AttrValue.Str("<strp_sup>") }
            AttrForm.REF_ADDR, AttrForm.SEC_OFFSET -> AttrValue.InfoRef(r.readOffset(is64))
            AttrForm.BLOCK1 -> block(r, r.u8())
            AttrForm.BLOCK2 -> block(r, r.u16())
            AttrForm.BLOCK4 -> block(r, r.u32().toInt())
            AttrForm.BLOCK, AttrForm.EXPRLOC -> block(r, r.uleb().toInt())
            AttrForm.DATA16 -> block(r, 16)
            AttrForm.IMPLICIT_CONST -> AttrValue.Num(0)
            AttrForm.STRX, AttrForm.STRX3 -> AttrValue.Num(r.uleb())
            AttrForm.ADDRX, AttrForm.ADDRX3 -> AttrValue.Num(r.uleb())
            AttrForm.LOCLISTX -> AttrValue.Num(r.uleb())
            AttrForm.RNGLISTX -> AttrValue.RangeRef(r.uleb(), indexed = true)
        }
    }

    private fun block(r: BoundedReader, n: Int): AttrValue {
        if (n < 0 || n > MAX_FORM_BLOCK) throw BoundsException("block length $n out of allowed range")
        return AttrValue.Raw(r.bytes(n))
    }

    private fun readStrp(r: BoundedReader, is64: Boolean, table: ByteArray?, sectionName: String): AttrValue {
        val off = r.readOffset(is64)
        if (table == null) return AttrValue.Str("<missing $sectionName@$off>")
        if (off < 0 || off >= table.size) {
            issues += ParseIssue("WARNING", "STROOB", "$sectionName offset $off out of bounds", sectionName, off)
            return AttrValue.Str("<oob $sectionName@$off>")
        }
        return AttrValue.Str(BoundedReader(table).nulStringAt(off.toInt()))
    }
}

fun BoundedReader.readOffset(is64: Boolean): Long = if (is64) u64() else u32()
