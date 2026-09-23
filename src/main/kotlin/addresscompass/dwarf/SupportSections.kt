@file:Suppress("USELESS_CAST")
package addresscompass.dwarf

import addresscompass.model.AddrRange
import addresscompass.model.FormValue
import addresscompass.model.ParseIssue
import addresscompass.model.Severity
import java.nio.ByteOrder

/** .debug_addr reader: validate the header then index entries. */
object AddrSection {
    fun readAddress(
        section: ByteArray?, base: Long, index: Long, addressSize: Int, version: Int, endian: ByteOrder,
        issues: MutableList<ParseIssue>,
    ): Long? {
        if (section == null) {
            issues += ParseIssue(Severity.WARNING, ".debug_addr", base, "DW_FORM_addrx but .debug_addr missing", true)
            return null
        }
        return try {
            val r = ByteReader(section, endian = endian)
            r.seek(base.toInt())
            if (version >= 5) {
                val unitLen = r.u32()
                r.u16(); r.u8(); r.u8()
            }
            val entryOff = r.pos + index * addressSize
            if (entryOff < 0 || entryOff + addressSize > section.size) {
                issues += ParseIssue(Severity.ERROR, ".debug_addr", base, "addrx $index OOB", true)
                return null
            }
            r.seek(entryOff)
            r.sizedInt(addressSize)
        } catch (e: SectionTruncatedException) {
            issues += ParseIssue(Severity.ERROR, ".debug_addr", base, e.message ?: "truncated", true)
            null
        } catch (e: OutOfBoundsReferenceException) {
            issues += ParseIssue(Severity.ERROR, ".debug_addr", base, e.message ?: "OOB", true)
            null
        }
    }
}

/**
 * Resolve range lists for both DWARF4 (.debug_ranges) and DWARF5 (.debug_rnglists).
 * [rangesAttrOffset] is the raw value of DW_AT_ranges (or the selected rnglistx target).
 * [cuBase] is CU low_pc / DW_AT_low_pc on the CU root used to resolve v4 base relocations.
 */
object RangeResolver {

    fun readV4(
        section: ByteArray?, offset: Long, cuBase: Long, selector: Int,
        endian: ByteOrder, issues: MutableList<ParseIssue>,
    ): List<AddrRange> {
        if (section == null) {
            issues += ParseIssue(Severity.WARNING, ".debug_ranges", offset, "DW_AT_ranges but section missing", true)
            return emptyList()
        }
        if (offset < 0 || offset >= section.size) {
            issues += ParseIssue(Severity.ERROR, ".debug_ranges", offset, "ranges offset OOB", true)
            return emptyList()
        }
        val out = mutableListOf<AddrRange>()
        try {
            val r = ByteReader(section, endian = endian)
            r.seek(offset.toInt())
            var base = cuBase
            var hops = 0
            while (r.remaining >= 8) {
                if (++hops > 1 shl 20) {
                    issues += ParseIssue(Severity.ERROR, ".debug_ranges", offset, "range list too long", true)
                    break
                }
                val begin = r.u64(); val end = r.u64()
                val sentinel = -1L
                if (begin == 0L && end == 0L) break
                if (begin == sentinel) {
                    base = end
                    continue
                }
                val lo = base + begin; val hi = base + end
                out += AddrRange(selector, lo, hi)
            }
        } catch (e: SectionTruncatedException) {
            issues += ParseIssue(Severity.ERROR, ".debug_ranges", offset, e.message ?: "truncated", true)
        }
        return out
    }

    fun readV5(
        section: ByteArray?, offset: Long, addressSize: Int,
        addrBase: Long, addrSection: ByteArray?, version: Int, endian: ByteOrder,
        issues: MutableList<ParseIssue>,
    ): List<AddrRange> {
        if (section == null) {
            issues += ParseIssue(Severity.WARNING, ".debug_rnglists", offset, "rnglists section missing", true)
            return emptyList()
        }
        if (offset < 0 || offset >= section.size) {
            issues += ParseIssue(Severity.ERROR, ".debug_rnglists", offset, "rnglist offset OOB", true)
            return emptyList()
        }
        val out = mutableListOf<AddrRange>()
        try {
            val r = ByteReader(section, endian = endian)
            r.seek(offset.toInt())
            var base = 0L
            var selector = 0
            var hops = 0
            while (r.remaining > 0) {
                if (++hops > 1 shl 20) {
                    issues += ParseIssue(Severity.ERROR, ".debug_rnglists", offset, "rnglist too long", true)
                    break
                }
                val kind = r.u8()
                when (kind) {
                    Dwarf.DW_RLE_end_of_list -> break
                    Dwarf.DW_RLE_base_addressx -> {
                        val idx = r.uleb()
                        base = AddrSection.readAddress(addrSection, addrBase, idx, addressSize, version, endian, issues) ?: base
                    }
                    Dwarf.DW_RLE_startx_endx -> {
                        val s = r.uleb(); val e = r.uleb()
                        val lo = AddrSection.readAddress(addrSection, addrBase, s, addressSize, version, endian, issues)
                        val hi = AddrSection.readAddress(addrSection, addrBase, e, addressSize, version, endian, issues)
                        if (lo != null && hi != null) out += AddrRange(selector, lo, hi)
                    }
                    Dwarf.DW_RLE_startx_length -> {
                        val s = r.uleb(); val len = r.uleb()
                        val lo = AddrSection.readAddress(addrSection, addrBase, s, addressSize, version, endian, issues)
                        if (lo != null) out += AddrRange(selector, lo, lo + len)
                    }
                    Dwarf.DW_RLE_offset_pair -> {
                        val s = r.uleb(); val e = r.uleb()
                        out += AddrRange(selector, base + s, base + e)
                    }
                    Dwarf.DW_RLE_base_address -> base = r.sizedInt(addressSize)
                    Dwarf.DW_RLE_start_end -> {
                        val lo = r.sizedInt(addressSize); val hi = r.sizedInt(addressSize)
                        out += AddrRange(selector, lo, hi)
                    }
                    Dwarf.DW_RLE_start_length -> {
                        val lo = r.sizedInt(addressSize); val len = r.uleb()
                        out += AddrRange(selector, lo, lo + len)
                    }
                    else -> {
                        issues += ParseIssue(Severity.ERROR, ".debug_rnglists", r.absoluteOffsetInSection(), "unknown rnglist kind 0x${kind.toString(16)}", true)
                        break
                    }
                }
            }
        } catch (e: SectionTruncatedException) {
            issues += ParseIssue(Severity.ERROR, ".debug_rnglists", offset, e.message ?: "truncated", true)
        }
        return out
    }
}

/** Resolve DW_FORM_strp / line_strp / strx into actual strings while reading attributes. */
object StringResolver {
    fun resolve(
        v: FormValue, form: Int, debugStr: ByteArray?, lineStr: ByteArray?, strOffsets: ByteArray?,
        strOffsetsBase: Long?, endian: ByteOrder, issues: MutableList<ParseIssue>,
    ): FormValue = when (v) {
        is FormValue.SecOffset -> {
            val target: ByteArray? = when (form) {
                Dwarf.DW_FORM_line_strp -> lineStr
                else -> debugStr
            }
            try {
                val r = ByteReader(target ?: ByteArray(0), endian = endian)
                FormValue.Str(r.stringAt(v.v.toInt()))
            } catch (e: RuntimeException) {
                issues += ParseIssue(Severity.WARNING, "strings", v.v, "unresolved strp form=0x${form.toString(16)}: ${e.message}", true)
                FormValue.Str("<?>")
            }
        }
        else -> v
    }
}
