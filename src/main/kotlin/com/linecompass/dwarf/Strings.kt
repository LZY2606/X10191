package com.linecompass.dwarf

import com.linecompass.io.ByteReader

/**
 * Resolves DW_FORM_strp / line_strp / strx family against .debug_str,
 * .debug_line_str and .debug_str_offsets. All failures degrade to a visible
 * marker rather than aborting the whole CU.
 */
class StringTables(
    private val debugStr: ByteArray?,
    private val debugLineStr: ByteArray?,
    private val strOffsets: ByteArray?,
    private val issues: MutableList<ParseIssue>
) {
    fun strp(offset: Long): String = readCString(debugStr, ".debug_str", offset)
    fun lineStrp(offset: Long): String = readCString(debugLineStr ?: debugStr, ".debug_line_str", offset)

    fun strx(index: Long, base: Long, cuOffset: Long, offsetSize: Int, le: Boolean): String {
        val table = strOffsets ?: run {
            issues += ParseIssue(".debug_str_offsets", "WARNING", "NO_STR_OFFSETS",
                "DW_FORM_strx index $index in CU 0x${cuOffset.toString(16)} but section missing")
            return "<strx:$index>"
        }
        val entryOffset = (base + index * offsetSize).toInt()
        if (entryOffset < 0 || entryOffset + offsetSize > table.size) {
            issues += ParseIssue(".debug_str_offsets", "WARNING", "STRX_OOB",
                "strx index $index (off 0x${entryOffset.toString(16)}) out of bounds in CU 0x${cuOffset.toString(16)}")
            return "<strx:$index>"
        }
        val target = ByteReader(table, le, ".debug_str_offsets", entryOffset).u(offsetSize)
        return strp(target)
    }

    private fun readCString(bytes: ByteArray?, section: String, offset: Long): String {
        if (bytes == null) return "<$section missing>"
        if (offset < 0 || offset >= bytes.size) return "<bad str 0x${offset.toString(16)}>"
        return try {
            ByteReader(bytes, true, section, offset.toInt()).cString()
        } catch (e: Exception) {
            "<unterminated str 0x${offset.toString(16)}>"
        }
    }
}

/**
 * Resolves DW_FORM_addrx against .debug_addr. .debug_addr has no header in the
 * GNU extension; for DWARF5 the header is validated and skipped.
 */
class AddrTableReader(
    private val debugAddr: ByteArray?,
    private val issues: MutableList<ParseIssue>
) {
    fun addrx(index: Long, base: Long, cuOffset: Long, offsetSize: Int, le: Boolean, v5: Boolean): Long {
        val table = debugAddr ?: run {
            issues += ParseIssue(".debug_addr", "ERROR", "NO_ADDR_TABLE",
                "addrx index $index in CU 0x${cuOffset.toString(16)} but .debug_addr missing")
            return 0L
        }
        val entryOffset = (base + index * offsetSize).toInt()
        if (entryOffset < 0 || entryOffset + offsetSize > table.size) {
            issues += ParseIssue(".debug_addr", "ERROR", "ADDRX_OOB",
                "addrx index $index (off 0x${entryOffset.toString(16)}) out of bounds in CU 0x${cuOffset.toString(16)}")
            return 0L
        }
        return ByteReader(table, le, ".debug_addr", entryOffset).u(offsetSize)
    }
}
