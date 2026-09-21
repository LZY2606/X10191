package com.compass

import com.compass.dwarf.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class Dwarf5Test {

    private fun elf(secs: Map<String, ByteArray>, textBase: Long = 0x500000L): ElfFile {
        val b = ElfBuilder().text(ByteArray(0x200), textBase)
        secs.forEach { (n, d) -> b.debug(n, d) }
        return ElfFile(b.build())
    }

    @Test
    fun dwarf5StrxAddrxRnglistsAndLineVersion() {
        val bundle = Dwarf5Fixtures.buildPair()
        val p = Dwarf.parse(elf(bundle.mainSections))
        val cu = p.cus.single()
        assertEquals(5, cu.version)
        assertEquals("src/v5.c", cu.name)
        // addrx + rnglists resolved outer range
        val outer = cu.dies.first { it.resolvedName == "v5_outer" }
        assertEquals(Dwarf5Fixtures.FUNC_LO, outer.ranges.single().low)
        assertEquals(Dwarf5Fixtures.FUNC_HI, outer.ranges.single().high)
        // line v5
        val lt = cu.lineTable!!
        assertEquals(5, lt.version)
        val row = lt.sequences.single().rows.first()
        assertEquals(Dwarf5Fixtures.FUNC_LO, row.address)
        assertEquals(10, row.line)
        assertTrue(lt.resolveFile(row.fileIndex).endsWith("v5.c"))
    }

    @Test
    fun mergedDwoProvidesInlineChain() {
        val bundle = Dwarf5Fixtures.buildPair()
        val main = Dwarf.parse(elf(bundle.mainSections))
        val dwo = Dwarf.parse(elf(bundle.dwoSections))
        val merged = DwoMerger.merge(main, listOf(dwo))
        val cu = merged.cus.single()
        assertTrue(cu.dwoResolved)
        val cands = QueryEngine(listOf(merged)).query(Dwarf5Fixtures.INL_LO + 4)
        val top = cands.first()
        assertEquals("v5_inline", top.functionName)
        assertTrue(top.inlineDepth >= 2, top.inlineChain.toString())
        assertEquals("v5_outer", top.inlineChain.last().name)
        assertEquals(5, top.lineTableVersion)
    }

    @Test
    fun missingDwoKeepsLineAndRangesButFlagsInlineIncomplete() {
        val bundle = Dwarf5Fixtures.buildPair()
        val main = Dwarf.parse(elf(bundle.mainSections))
        // deliberately never import the dwo
        val merged = DwoMerger.merge(main, emptyList())
        val cu = merged.cus.single()
        assertFalse(cu.dwoResolved)
        // line program still resolves
        val cands = QueryEngine(listOf(merged)).query(Dwarf5Fixtures.INL_LO)
        assertTrue(cands.isNotEmpty())
        val c = cands.first()
        assertEquals(30, c.line)
        // trust note explicitly explains what remains reliable
        assertTrue(c.trustNotes.any { it.contains("缺少 .dwo") }, c.trustNotes.toString())
        // inline tree from dwo is absent, but outer skeleton range exists
        assertTrue(c.inlineChain.none { it.name == "v5_inline" })
    }
}
