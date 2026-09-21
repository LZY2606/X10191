package compass.dwarf

import compass.elf.Cursor
import compass.elf.SliceOutOfBoundsException
import compass.elf.sleb128
import compass.elf.uleb128

/**
 * Walks .debug_info / .debug_info.dwo, producing [CompilationUnit]s.
 *
 * Robustness rules:
 *  - abbreviation tables are cached by section offset;
 *  - unknown forms are skipped with a *measured* size so the cursor stays aligned;
 *  - DIE recursion and reference-following are depth/visit bounded.
 */
class UnitParser(private val data: DwarfData, private val isDwo: Boolean) {
    private val infoBytes = if (isDwo) data.debugInfoDwo else data.debugInfo
    private val abbrevBytes = if (isDwo) data.debugAbbrevDwo else data.debugAbbrev
    private val abbrevCache = HashMap<Long, AbbrevTable>()

    fun parse(): List<CompilationUnit> {
        val bytes = infoBytes ?: return emptyList()
        if (abbrevBytes == null) {
            data.sectionErrors += (if (isDwo) "debug_abbrev.dwo" else "debug_abbrev") to "missing"
            return emptyList()
        }
        val c = data.cursor(bytes)
        val units = ArrayList<CompilationUnit>()
        var idx = 0
        while (c.remaining > 0) {
            val unitStart = c.offset
            val cu = try {
                parseOne(c, idx++, unitStart)
            } catch (e: SliceOutOfBoundsException) {
                data.warnings += "CU at offset $unitStart truncated: ${e.message}"
                break
            } catch (e: DwarfParseException) {
                data.warnings += "CU at offset $unitStart unreadable: ${e.message}"
                break
            }
            units.add(cu)
            // Skip deterministically to the declared unit end regardless of DIE parse quirks.
            val end = (unitStart + cu.unitLength + headerLen(cu.is64)).toInt()
            if (end <= c.offset || end > bytes.size) {
                if (c.offset >= bytes.size) break
            } else {
                c.seek(end)
            }
        }
        return units
    }

    private fun headerLen(is64: Boolean): Int = if (is64) 12 else 4

    private fun parseOne(c: Cursor, index: Int, unitStart: Int): CompilationUnit {
        val lengthField = c.u32()
        val is64: Boolean
        val unitLength: Long
        if (lengthField == 0xFFFFFFFFL) {
            is64 = true
            unitLength = c.u64().toLong()
        } else {
            is64 = false
            unitLength = lengthField
        }
        if (unitLength <= 0 || unitStart + headerLen(is64) + unitLength > c.size) {
            throw DwarfParseException("unit length $unitLength out of bounds at $unitStart")
        }
        val unitEnd = (unitStart + headerLen(is64) + unitLength).toInt()
        val version = c.u16().toInt()
        if (version !in 2..5) throw DwarfParseException("unsupported DWARF version $version")

        var unitType = 1
        var addressSize = 8
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = c.u8()
            addressSize = c.u8()
            abbrevOffset = readOffset(c, is64)
        } else {
            abbrevOffset = readOffset(c, is64)
            addressSize = c.u8()
        }
        if (addressSize !in 1..8) throw DwarfParseException("bad address_size $addressSize")

        // DWARF 5 unit type 2 (dwo split compile units): header continues with dwo_id.
        var dwoId: ULong? = null
        if (version >= 5 && unitType == 2) dwoId = c.u64()
        // GNU split DWARF (DWARF4): dwo_id is an attribute on the root DIE.

        val dieAreaStart = c.offset
        val abbrev = abbrevCache.getOrPut(abbrevOffset) {
            val ab = abbrevBytes!!
            if (abbrevOffset < 0 || abbrevOffset >= ab.size) {
                throw DwarfParseException("abbrev offset $abbrevOffset out of section")
            }
            AbbrevTable.parse(data.cursor(ab), abbrevOffset.toInt())
        }

        val strOffsetsBase = 0L // read from root attribute below
        val addrBaseRelative = 0L
        val rngBase = 0L

        val dieReader = DieReader(data, isDwo, abbrev, addressSize, is64, version, dieAreaStart, unitEnd)
        val root = dieReader.readTree()

        // DWARF 4 GNU dwo id.
        if (dwoId == null) {
            root.attr(Attr.DW_AT_GNU_dwo_id)?.value?.asLong?.let { dwoId = it.toULong() }
            root.attr(Attr.DW_AT_dwo_id5)?.value?.asLong?.let { dwoId = it.toULong() }
        }

        return CompilationUnit(
            index, data, isDwo, unitStart, version, unitLength, is64,
            abbrevOffset, addressSize, dwoId, root, abbrev, dieAreaStart,
            strOffsetsBase, addrBaseRelative, rngBase,
        )
    }

    private fun readOffset(c: Cursor, is64: Boolean): Long =
        if (is64) c.u64().toLong() else c.u32()
}

/**
 * Reads the DIE tree for one unit. A maximum depth and total DIE count protect
 * against cyclic/malformed abbreviation nesting (DIE nesting itself terminates via
 * null codes, but corrupted data can hide those).
 */
internal class DieReader(
    private val data: DwarfData,
    private val isDwo: Boolean,
    private val abbrev: AbbrevTable,
    private val addressSize: Int,
    private val is64: Boolean,
    private val dwarfVersion: Int,
    private val dieAreaStart: Int,
    private val unitEnd: Int,
) {
    private var dieCount = 0
    private val strOffsets = if (isDwo) data.debugStrOffsetsDwo else data.debugStrOffsets
    private val debugStr = if (isDwo) data.debugStrDwo else data.debugStr
    private val debugAddr = if (isDwo) data.debugAddrDwo else data.debugAddr

    fun readTree(): Die {
        val root = readDies(0)
            ?: throw DwarfParseException("CU has no root DIE")
        return root
    }

    private fun readDies(depth: Int): Die? {
        if (depth > MAX_DIE_DEPTH) throw DwarfParseException("DIE nesting too deep (> $MAX_DIE_DEPTH)")
        if (dieCount >= MAX_DIES_PER_UNIT) throw DwarfParseException("too many DIEs in unit")
        val code = c().uleb128().toInt()
        if (code == 0) return null
        val decl = abbrev[code] ?: throw DwarfParseException("unknown abbrev code $code at ${curPos() - 1}")
        val offset = curPos() - 1 - dieAreaStart
        val attrs = ArrayList<Attribute>(decl.specs.size)
        for ((attrName, rawForm) in decl.specs) {
            var form = rawForm
            if (form == Form.INDIRECT) form = c().uleb128().toInt()
            val value = readFormValue(attrName, form, decl, attrs)
            attrs.add(Attribute(attrName, form, value))
        }
        dieCount++
        val children = ArrayList<Die>()
        if (decl.hasChildren) {
            while (true) {
                if (curPos() >= unitEnd) {
                    data.warnings += "DIE tree reached unit end without terminating null"
                    break
                }
                val child = readDies(depth + 1) ?: break
                children.add(child)
            }
        }
        return Die(offset, decl.tag, attrs, depth, children)
    }

    private var theCursor: Cursor? = null
    private fun c(): Cursor {
        if (theCursor == null) {
            val bytes = (if (isDwo) data.debugInfoDwo else data.debugInfo)!!
            theCursor = Cursor(bytes, dieAreaStart, unitEnd - dieAreaStart, data.littleEndian)
        }
        return theCursor!!
    }
    private fun curPos(): Int = dieAreaStart + c().offset

    private fun readAddr(): ULong = when (addressSize) {
        1 -> c().u8().toULong()
        2 -> c().u16().toULong()
        4 -> c().u32().toULong()
        8 -> c().u64()
        else -> throw DwarfParseException("unsupported address size $addressSize")
    }

    private fun readRefSize(bytes: Int): Long = when (bytes) {
        1 -> c().u8().toLong()
        2 -> c().u16().toLong()
        3 -> {
            val b0 = c().u8().toLong()
            val b1 = c().u16().toLong()
            b0 or (b1 shl 8)
        }
        4 -> c().u32()
        8 -> c().u64().toLong()
        else -> throw DwarfParseException("bad ref size $bytes")
    }

    private fun readFormValue(attrName: Int, form: Int, decl: AbbrevDecl, prior: List<Attribute>): FormValue {
        return when (form) {
            Form.ADDR -> FormValue.Addr(readAddr())
            Form.DATA1 -> FormValue.Number(c().u8().toLong())
            Form.DATA2 -> FormValue.Number(c().u16().toLong())
            Form.DATA4 -> FormValue.Number(c().u32())
            Form.DATA8 -> FormValue.Number(c().u64().toLong())
            Form.SDATA -> FormValue.Number(c().sleb128())
            Form.UDATA -> FormValue.Number(c().uleb128().toLong())
            Form.FLAG -> FormValue.Number(c().u8().toLong())
            Form.FLAG_PRESENT -> FormValue.Number(1L)
            Form.STRING -> FormValue.Str(c().zeroString())
            Form.STRP -> readStrp()
            Form.LINE_STRP -> readLineStrp()
            Form.REF_ADDR -> FormValue.Number(readRefSize(if (is64) 8 else 4))
            Form.REF1, Form.STRX1, Form.ADDRX1 -> FormValue.Number(readRefSize(1))
            Form.REF2, Form.STRX2, Form.ADDRX2 -> FormValue.Number(readRefSize(2))
            Form.REF4, Form.STRX4, Form.ADDRX4 -> FormValue.Number(readRefSize(4))
            Form.REF8 -> FormValue.Number(readRefSize(8))
            Form.REF_UDATA, Form.STRX, Form.ADDRX -> FormValue.Number(c().uleb128().toLong())
            Form.SEC_OFFSET -> FormValue.SecOffset(readRefSize(if (is64) 8 else 4))
            Form.EXPRLOC -> { val n = c().uleb128().toInt(); FormValue.Exprloc(c().bytes(n)) }
            Form.BLOCK1 -> { val n = c().u8(); FormValue.Block(c().bytes(n)) }
            Form.BLOCK2 -> { val n = c().u16(); FormValue.Block(c().bytes(n)) }
            Form.BLOCK4 -> { val n = c().u32().toInt(); FormValue.Block(c().bytes(n)) }
            Form.BLOCK -> { val n = c().uleb128().toInt(); FormValue.Block(c().bytes(n)) }
            Form.STRX3, Form.ADDRX3 -> FormValue.Number(readRefSize(3))
            Form.GNUE_ADDR_INDEX, Form.GNUE_STR_INDEX, Form.GNUE_RANGES_INDEX ->
                FormValue.Number(c().uleb128().toLong())
            else -> skipUnknownForm(form)
        }
    }

    private fun readStrp(): FormValue {
        val off = readRefSize(if (is64) 8 else 4)
        return data.readString(debugStr, off.toInt())?.let { FormValue.Str(it) }
            ?: FormValue.Unknown(Form.STRP, if (is64) 8 else 4)
    }

    private fun readLineStrp(): FormValue {
        val off = readRefSize(if (is64) 8 else 4)
        return data.readString(data.debugLineStr, off.toInt())?.let { FormValue.Str(it) }
            ?: FormValue.Unknown(Form.LINE_STRP, if (is64) 8 else 4)
    }

    /**
     * Unknown forms have a fixed width defined by the DWARF spec. We consume exactly
     * that many bytes and record [FormValue.Unknown] so parsing stays aligned and the
     * attribute is visibly unresolved instead of poisoning subsequent DIEs.
     */
    private fun skipUnknownForm(form: Int): FormValue {
        val n = when (form) {
            in 0x20..0x24 -> 8
            Form.DATA16 -> 16
            Form.REF_SIG8 -> 8
            else -> {
                data.warnings += "unknown form 0x${form.toString(16)} with undeterminable size; stopping CU"
                throw DwarfParseException("unskippable form 0x${form.toString(16)}")
            }
        }
        c().bytes(n)
        return FormValue.Unknown(form, n)
    }

    companion object {
        const val MAX_DIE_DEPTH = 128
        const val MAX_DIES_PER_UNIT = 200_000
    }
}
