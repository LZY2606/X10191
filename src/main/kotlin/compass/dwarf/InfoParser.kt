package compass.dwarf

import compass.ByteReader
import compass.Ref

/** Thrown when a CU contains a form the parser cannot size; the CU is isolated. */
class UnknownFormException(val form: Int, message: String) : RuntimeException(message)

/** Thrown for a self/forward reference chain that exceeds the hop budget. */
class ReferenceHopException(message: String) : RuntimeException(message)

/** Parsed unit header + DIE tree. */
class RawUnit(
    val cuOffset: Long,
    val unitLength: Long,
    val version: Int,
    val is64Bit: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val dwoId: Long?,
    val rootOffset: Long,
    val root: Die,
    val warnings: MutableList<String> = mutableListOf(),
)

object InfoParser {

    const val MAX_DIE_DEPTH = 128

    fun parseUnits(info: ByteArray, abbrevTables: Map<Long, Map<Long, AbbrevParser.Decl>>): List<RawUnit> {
        val r = ByteReader(info)
        val units = ArrayList<RawUnit>()
        while (r.remaining > 0) {
            val cuStart = r.pos
            val (is64, unitLength) = readInitialLength(r)
            val unitEnd = if (unitLength == 0L) r.end else {
                val lenFieldSize = if (is64) 12 else 4
                cuStart + lenFieldSize + unitLength.toIntExact()
            }
            if (unitEnd > r.end) {
                // Trailing truncated unit: stop scanning, keep everything before it.
                break
            }
            val version = r.u16()
            var unitType = DW.UT_compile
            var addressSize = 4
            var abbrevOffset = 0L
            var dwoId: Long? = null
            if (version >= 5) {
                unitType = r.u8()
                addressSize = r.u8()
                abbrevOffset = r.offset(if (is64) 8 else 4)
                when (unitType) {
                    DW.UT_skeleton, DW.UT_split_compile -> dwoId = r.u64()
                    DW.UT_type, DW.UT_split_type -> {
                        r.u64() // type signature
                        r.offset(if (is64) 8 else 4) // type offset
                    }
                }
            } else {
                abbrevOffset = r.offset(if (is64) 8 else 4)
                addressSize = r.u8()
            }
            val table = abbrevTables[abbrevOffset]
            val rootOffset = r.pos.toLong()
            val warnings = mutableListOf<String>()
            if (table == null) {
                warnings.add("no abbrev table at offset 0x${abbrevOffset.toString(16)}; DIE tree skipped")
                r.seek(unitEnd)
                units += RawUnit(cuStart.toLong(), unitLength, version, is64, unitType,
                    addressSize, abbrevOffset, dwoId, rootOffset,
                    Die(rootOffset, DW.TAG_compile_unit, emptyList(), emptyList()), warnings)
                continue
            }
            val ctx = DieContext(r, table, is64, addressSize, version)
            val root = try {
                val die = ctx.readDieTree(0)
                if (r.pos > unitEnd) {
                    warnings.add("DIE bytes overran the unit; tree retained but may be incomplete")
                }
                die
            } catch (e: UnknownFormException) {
                warnings.add("${DW.formName(e.form)} is not supported; this CU's DIE tree was truncated at the first unknown form")
                r.seek(unitEnd)
                Die(rootOffset, DW.TAG_compile_unit, emptyList(), emptyList())
            }
            r.seek(unitEnd)
            units += RawUnit(cuStart.toLong(), unitLength, version, is64, unitType,
                addressSize, abbrevOffset, dwoId, rootOffset, root, warnings)
        }
        return units
    }

    private class DieContext(
        val r: ByteReader,
        val abbrev: Map<Long, AbbrevParser.Decl>,
        val is64: Boolean,
        val addressSize: Int,
        val version: Int,
    ) {
        fun readDieTree(depth: Int): Die {
            if (depth > MAX_DIE_DEPTH) throw IllegalStateException("DIE nesting exceeds $MAX_DIE_DEPTH")
            val offset = r.pos.toLong()
            val code = r.uleb()
            if (code == 0L) return Die(offset, 0, emptyList(), emptyList())
            val decl = abbrev[code]
                ?: throw IllegalStateException("abbrev code $code not found in table")
            val attrs = decl.entries.map { e ->
                val rawForm = if (e.form == DW.FORM_indirect) readIndirectForm() else e.form
                val value: AttrValue = if (e.form == DW.FORM_implicit_const) {
                    AttrValue.Num(e.implicitConst!!)
                } else {
                    readValue(rawForm)
                }
                Attribute(e.attr, rawForm, value)
            }
            val children = ArrayList<Die>()
            if (decl.hasChildren) {
                while (true) {
                    if (r.remaining == 0) break
                    val mark = r.pos
                    val child = readDieTree(depth + 1)
                    if (child.tag == 0) break // null terminating DIE
                    children.add(child)
                    if (r.pos == mark) break
                }
            }
            return Die(offset, decl.tag, attrs, children)
        }

        private fun readIndirectForm(): Int = r.uleb().toIntExact()

        private fun readValue(form: Int): AttrValue = when (form) {
            DW.FORM_addr -> AttrValue.Addr(r.addr(addressSize))
            DW.FORM_data1 -> AttrValue.Num(r.u8().toLong())
            DW.FORM_flag_present -> AttrValue.Flag(true)
            DW.FORM_data2 -> AttrValue.Num(r.u16().toLong())
            DW.FORM_data4 -> AttrValue.Num(r.u32())
            DW.FORM_data8 -> AttrValue.Num(r.u64())
            DW.FORM_data16, DW.FORM_data16b -> AttrValue.Bytes(r.bytes(16))
            DW.FORM_udata -> AttrValue.Num(r.uleb())
            DW.FORM_sdata -> AttrValue.Num(r.sleb())
            DW.FORM_flag -> AttrValue.Flag(r.u8() != 0)
            DW.FORM_string -> AttrValue.Str(r.cString())
            DW.FORM_strp, DW.FORM_line_strp, DW.FORM_strp_sup ->
                AttrValue.SecOffset(r.offset(if (is64) 8 else 4))
            DW.FORM_sec_offset -> AttrValue.SecOffset(r.offset(if (is64) 8 else 4))
            DW.FORM_ref1 -> AttrValue.Reference(Ref(form, r.u8().toLong()))
            DW.FORM_ref2 -> AttrValue.Reference(Ref(form, r.u16().toLong()))
            DW.FORM_ref4, DW.FORM_ref_sup4 -> AttrValue.Reference(Ref(form, r.u32()))
            DW.FORM_ref8 -> AttrValue.Reference(Ref(form, r.u64()))
            DW.FORM_ref_udata -> AttrValue.Reference(Ref(form, r.uleb()))
            DW.FORM_ref_addr -> AttrValue.Reference(Ref(form, r.offset(if (is64) 8 else 4)))
            DW.FORM_ref_sig8 -> AttrValue.Reference(Ref(form, r.u64()))
            DW.FORM_block1 -> AttrValue.Bytes(r.bytes(r.u8()))
            DW.FORM_block2 -> AttrValue.Bytes(r.bytes(r.u16()))
            DW.FORM_block4 -> AttrValue.Bytes(r.bytes(r.u32().toIntExact()))
            DW.FORM_block, DW.FORM_exprloc -> {
                val n = r.uleb().toIntExact(); AttrValue.Bytes(r.bytes(n))
            }
            DW.FORM_strx, DW.FORM_strx1, DW.FORM_strx2, DW.FORM_strx3, DW.FORM_strx4,
            DW.FORM_GNU_str_index -> AttrValue.StrIndex(readIndex(form))
            DW.FORM_addrx, DW.FORM_addrx1, DW.FORM_addrx2, DW.FORM_addrx3, DW.FORM_addrx4,
            DW.FORM_GNU_addr_index -> AttrValue.AddrIndex(readIndex(form))
            DW.FORM_rnglistx, DW.FORM_loclistx -> AttrValue.Num(r.uleb())
            else -> {
                // Do NOT consume anything: with an unknown form the cursor cannot be
                // recovered inside the CU, so abort before producing misaligned DIEs.
                throw UnknownFormException(form, "unknown form 0x${form.toString(16)}")
            }
        }

        private fun readIndex(form: Int): Long = when (form) {
            DW.FORM_strx1, DW.FORM_addrx1 -> r.u8().toLong()
            DW.FORM_strx2, DW.FORM_addrx2 -> r.u16().toLong()
            DW.FORM_strx3, DW.FORM_addrx3 -> r.u32()
            DW.FORM_strx4, DW.FORM_addrx4 -> r.u32()
            else -> r.uleb()
        }
    }

    fun readInitialLength(r: ByteReader): Pair<Boolean, Long> {
        val first = r.u32()
        return if (first == 0xffffffffL) {
            true to r.u64()
        } else {
            false to first
        }
    }

    private fun Long.toIntExact(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw IllegalStateException("length too large: $this")
        return toInt()
    }
}
