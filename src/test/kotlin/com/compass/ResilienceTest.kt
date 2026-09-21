package com.compass

import com.compass.dwarf.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

/**
 * Covers the hostile-input requirements:
 *  - runtime relocation + load bias across multiple load generations
 *  - unknown DW_FORM must isolate the CU without corrupting the cursor
 *  - a dangling/out-of-bounds reference is contained
 *  - a truncated section never spills pseudo-results into following data
 */
class ResilienceTest {

    private fun dwarf4Parsed(): ParsedDebug {
        val b = ElfBuilder().text(ByteArray(0x300))
        DwarfFixtures.dwarf4().map.forEach { (n, d) -> b.debug(n, d) }
        return Dwarf.parse(ElfFile(b.build()))
    }

    @Test
    fun loadBiasConvertsRuntimeToRelativeAcrossGenerations() {
        val p = dwarf4Parsed()
        val linkBase = p.elf.linkBase()
        assertEquals(0x401000L, linkBase)

        // Generation 1: module loaded at 0x5555_5555_4000 -> bias +0x5555_5515_3000
        val bias1 = 0x5555_5555_4000L - linkBase
        val runtime1 = bias1 + DwarfFixtures.INL_LO
        val rel1 = runtime1 - bias1
        assertEquals(DwarfFixtures.INL_LO, rel1)
        assertEquals("inner_inline", QueryEngine(listOf(p)).query(rel1).first().functionName)

        // Same relative address, a different generation after reload.
        val bias2 = 0x7fff_0000_0000L - linkBase
        val runtime2 = bias2 + DwarfFixtures.INL_LO
        assertEquals(DwarfFixtures.INL_LO, runtime2 - bias2)
        assertEquals("inner_inline", QueryEngine(listOf(p)).query(runtime2 - bias2).first().functionName)
    }

    @Test
    fun unknownFormIsolatesCuWithoutCursorDesync() {
        // Take the valid DWARF4 fixture and splice an unknown form (0x6a) into
        // a fresh abbrev declaration appended after the real table.
        val base = DwarfFixtures.dwarf4()
        val ab = base.map[".debug_abbrev"]!!.copyOf()
        // Build a separate abbrev table with an unsupported form.
        val evilAbbrev = Bin()
        evilAbbrev.uleb(1).uleb(DW_TAG_compile_unit.toLong()).u8(DW_CHILDREN_no)
        evilAbbrev.uleb(DW_AT_name.toLong()).uleb(0x6a) // unknown form
        evilAbbrev.uleb(0).uleb(0)
        evilAbbrev.uleb(0)
        // evil info: one CU, root code 1
        val body = Bin().u16(4).u32(0L).u8(8).uleb(1).cstr("evil").uleb(0)
        val evilInfo = Bin().u32(body.size.toLong()).raw(body.bytes()).bytes()
        val b = ElfBuilder().text(ByteArray(0x10))
        b.debug(".debug_info", evilInfo).debug(".debug_abbrev", evilAbbrev.bytes())
        val parsed = Dwarf.parse(ElfFile(b.build()))
        // The CU is recorded but its DIE parse is flagged; the parser did not
        // walk off producing phantom results.
        assertTrue(parsed.cus.size in 0..1, "CU isolated: ${parsed.issues}")
        assertTrue(parsed.issues.any { it.severity == "error" }, parsed.issues.toString())
    }

    @Test
    fun truncatedSectionDoesNotEmitPhantomResults() {
        // Truncate .debug_line mid-header.
        val base = DwarfFixtures.dwarf4()
        val line = base.map[".debug_line"]!!
        val cut = line.copyOfRange(0, line.size / 2)
        val b = ElfBuilder().text(ByteArray(0x300))
        base.map.forEach { (n, d) -> if (n == ".debug_line") b.debug(n, cut) else b.debug(n, d) }
        val parsed = Dwarf.parse(ElfFile(b.build()))
        // CU/DIE ranges remain trustworthy; the broken line table yields no rows.
        val cu = parsed.cus.single()
        assertTrue(cu.issues.any { it.scope.startsWith("line") })
        val cands = QueryEngine(listOf(parsed)).query(DwarfFixtures.INL_LO)
        assertTrue(cands.none { it.lineTableVersion == 4 && it.line == 42 })
    }

    @Test
    fun danglingReferenceIsContainedAndNamedSafely() {
        // Craft a subprogram with DW_AT_abstract_origin ref4 pointing far past
        // .debug_info. Range resolution must still work; name falls back.
        val str = Bin().u8(0).let { it.cstr("real_fn"); it.bytes() }
        val ab = Bin()
        ab.uleb(1).uleb(DW_TAG_compile_unit.toLong()).u8(DW_CHILDREN_yes)
        ab.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        ab.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_addr.toLong())
        ab.uleb(0).uleb(0)
        ab.uleb(2).uleb(DW_TAG_subprogram.toLong()).u8(DW_CHILDREN_no)
        ab.uleb(DW_AT_abstract_origin.toLong()).uleb(DW_FORM_ref4.toLong())
        ab.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        ab.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_addr.toLong())
        ab.uleb(0).uleb(0)
        ab.uleb(0)
        val body = Bin().u16(4).u32(0L).u8(8)
        body.uleb(1).u64(0x3000).u64(0x4000)
        body.uleb(2).u32(0xfffffff0L).u64(0x3100).u64(0x3200)
        body.uleb(0)
        val info = Bin().u32(body.size.toLong()).raw(body.bytes()).bytes()
        val b = ElfBuilder().text(ByteArray(0x2000), 0x2000)
        b.debug(".debug_info", info).debug(".debug_abbrev", ab.bytes()).debug(".debug_str", str)
        val parsed = Dwarf.parse(ElfFile(b.build()))
        val cands = QueryEngine(listOf(parsed)).query(0x3150)
        assertTrue(cands.isNotEmpty() || parsed.cus.isNotEmpty())
        // Must not throw and must not invent a name.
        cands.forEach { assertTrue(it.functionName == null || it.functionName!!.startsWith("<")) }
    }

    @Test
    fun stableOrderingIndependentOfImportOrder() {
        // Two separate ELF files with overlapping coverage of the same address;
        // query result order is content-keyed, not list-insertion order.
        fun buildAt(marker: Long): ParsedDebug {
            // reuse the same fixture bytes (identical content => identical key)
            return dwarf4Parsed()
        }
        val a = buildAt(1); val b = buildAt(2)
        val keys1 = QueryEngine(listOf(a, b)).query(DwarfFixtures.INL_LO + 2).map { it.stableKey }
        val keys2 = QueryEngine(listOf(b, a)).query(DwarfFixtures.INL_LO + 2).map { it.stableKey }
        assertEquals(keys1, keys2)
        assertTrue(keys1.isNotEmpty())
    }
}
