package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException
import compass.DwarfTruncationException
import compass.unitLength

/**
 * String / address indirection resolution for attribute values.
 *
 * Bases follow the DWARF 5 rules:
 *  - .debug_str_offsets contribution starts at DW_AT_str_offsets_base; in GNU split v4 it is
 *    given by DW_AT_GNU_str_offsets_base (we accept the v5 attribute too).
 *  - .debug_addr contribution starts at DW_AT_addr_base (v5; header skipped) or
 *    DW_AT_GNU_addr_base (v4, raw entries, no header).
 */
fun AttrValue.asString(obj: DebugObject, cu: CompilationUnit): String? = when (this) {
    is AttrValue.Str -> v
    is AttrValue.StrPtr -> readStringAt(obj.section(if (lineString) ".debug_line_str" else ".debug_str"), offset)
    is AttrValue.StrIndex -> {
        val base = strOffsetsBase(obj, cu) ?: return null
        val entrySize = if (cu.is64BitDwarf) 8 else 4
        val off = base + index.toLong() * entrySize
        val target = readStringOffset(obj.section(".debug_str_offsets"), off, entrySize) ?: return null
        readStringAt(obj.section(".debug_str"), target)
    }
    else -> null
}

fun AttrValue.asLong(): Long? = when (this) {
    is AttrValue.Constant -> v
    is AttrValue.UConstant -> v.toLong()
    is AttrValue.Addr -> v
    is AttrValue.Flag -> 1L
    else -> null
}

fun AttrValue.asUlong(): ULong? = when (this) {
    is AttrValue.UConstant -> v
    is AttrValue.Constant -> v.toULong()
    is AttrValue.Addr -> v.toULong()
    else -> null
}

private fun readStringAt(section: ByteArray?, off: Long): String? {
    if (section == null || off < 0 || off >= section.size) return null
    val end = (off.toInt() until section.size).firstOrNull { section[it].toInt() == 0 } ?: return null
    return String(section, off.toInt(), end - off.toInt(), Charsets.UTF_8)
}

private fun readStringOffset(section: ByteArray?, off: Long, entrySize: Int): Long? {
    if (section == null || off < 0 || off + entrySize > section.size) return null
    val r = ByteReader(section, off.toInt(), section.size, true)
    return if (entrySize == 8) r.u64() else r.u32()
}

/** Effective start offset of this CU's .debug_str_offsets contribution (past the 8/16-byte header). */
fun strOffsetsBase(obj: DebugObject, cu: CompilationUnit): Long? {
    cu.root.attr(DW.AT_STR_OFFSETS_BASE)?.let { v ->
        return (v as? AttrValue.SecOffset)?.offset ?: v.asLong()
    }
    // GNU fission: .debug_str_offsets base absent on root; table typically begins at 0 of section.
    return if (obj.section(".debug_str_offsets") != null) 0L else null
}

/**
 * Resolve an addrx index against the CU's .debug_addr contribution.
 * Returns null (with a CU issue recorded by callers where needed) if data is missing.
 */
fun resolveAddrx(obj: DebugObject, cu: CompilationUnit, index: ULong): Long? {
    val (base, addrSize) = addrContribution(obj, cu) ?: return null
    val section = obj.section(".debug_addr") ?: return null
    val off = base + index.toLong() * addrSize
    if (off < 0 || off + addrSize > section.size) return null
    val r = ByteReader(section, off.toInt(), section.size, obj.littleEndian)
    return when (addrSize) {
        4 -> r.u32(); 8 -> r.u64(); 2 -> r.u16().toLong(); 1 -> r.u8().toLong()
        else -> null
    }
}

data class AddrContribution(val base: Long, val addrSize: Int)

fun addrContribution(obj: DebugObject, cu: CompilationUnit): AddrContribution? {
    val addrSize = cu.addressSize
    cu.root.attr(DW.AT_ADDR_BASE)?.let { v ->
        val declared = (v as? AttrValue.SecOffset)?.offset ?: v.asLong()
        // Per DWARF 5, addr_base points at the first entry (header already skipped).
        return declared?.let { AddrContribution(it, addrSize) }
    }
    cu.root.attr(DW.AT_GNU_ADDR_BASE)?.let { v ->
        val declared = (v as? AttrValue.SecOffset)?.offset ?: v.asLong()
        // GNU split .debug_addr has no header.
        return declared?.let { AddrContribution(it, addrSize) }
    }
    // Plain DWARF 5 CUs without addr_base: contribution starts at section beginning (header skipped).
    obj.section(".debug_addr")?.let { return AddrContribution(skipAddrHeader(obj, 0L), addrSize) }
    return null
}

/** The .debug_addr header (DWARF 5) is 8 (32-bit DWARF) or 16 (64-bit) bytes. */
private fun skipAddrHeader(obj: DebugObject, declared: Long): Long {
    val section = obj.section(".debug_addr") ?: return declared
    if (declared + 4 > section.size) return declared
    val r = ByteReader(section, declared.toInt(), section.size, obj.littleEndian)
    val lenFirst = r.u32()
    return if (lenFirst == 0xffffffffUL.toLong()) declared + 16 else declared + 8
}
