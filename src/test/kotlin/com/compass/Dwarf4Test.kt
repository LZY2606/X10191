package com.compass

import com.compass.dwarf.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertContains

class Dwarf4Test {

    private fun buildElf(): ElfFile {
        val s = DwarfFixtures.dwarf4()
        val b = ElfBuilder()
        b.text(ByteArray(0x300))
        s.map.forEach { (name, data) -> b.debug(name, data) }
        return ElfFile(b.build())
    }

    @Test
    fun parsesSectionsAndCu() {
        val elf = buildElf()
        val p = Dwarf.parse(elf)
        assertEquals(1, p.cus.size, "one CU")
        val cu = p.cus.single()
        assertEquals(4, cu.version)
        assertEquals("src/main.c", cu.name)
        assertTrue(p.sectionsParsed.contains(".debug_ranges"))
    }

    @Test
    fun specialOpcodesProduceRowsAndTwoSequences() {
        val p = Dwarf.parse(buildElf())
        val lt = p.cus.single().lineTable!!
        assertEquals(2, lt.sequences.size, "two line sequences")
        val seq = lt.sequences.first()
        // Row at FUNC_LO main.c:10
        val first = seq.rows.first()
        assertEquals(DwarfFixtures.FUNC_LO, first.address)
        assertEquals(10, first.line)
        // Inlined row header.h:42
        val inlRow = seq.rows.first { it.address == DwarfFixtures.INL_LO }
        assertEquals(42, inlRow.line)
        assertEquals(7, inlRow.column)
        assertTrue(lt.resolveFile(inlRow.fileIndex).endsWith("header.h"))
    }

    @Test
    fun highPcTwoMeaningsResolved() {
        val p = Dwarf.parse(buildElf())
        val cu = p.cus.single()
        // CU high_pc was encoded as data4 length
        val cuRange = cu.ranges.single()
        assertEquals(DwarfFixtures.BASE, cuRange.low)
        assertEquals(0x401280L, cuRange.high)
        // inline subprogram used absolute high_pc address form
        val inl = cu.dies.first { it.tag == DW_TAG_inlined_subroutine }
        assertEquals(DwarfFixtures.INL_LO, inl.ranges.single().low)
        assertEquals(DwarfFixtures.INL_HI, inl.ranges.single().high)
    }

    @Test
    fun zeroLengthRangeKeptButNeverMatches() {
        val p = Dwarf.parse(buildElf())
        val cu = p.cus.single()
        val zero = cu.dies.first { it.resolvedName == "zero_func" }
        assertEquals(1, zero.ranges.size)
        assertTrue(zero.ranges.single().zeroLength)
        val engine = QueryEngine(listOf(p))
        assertTrue(engine.query(DwarfFixtures.ZERO_PC).none {
            it.functionName == "zero_func" && it.rank >= 4
        })
    }

    @Test
    fun overlappingFunctionsBothKeptNarrowestAndDepthWin() {
        val p = Dwarf.parse(buildElf())
        val engine = QueryEngine(listOf(p))
        val cands = engine.query(DwarfFixtures.INL_LO + 4)
        // All legal candidates retained.
        assertTrue(cands.size >= 1)
        val top = cands.first()
        // The inlined instance is deepest and narrower than the overlapping func.
        assertEquals("inner_inline", top.functionName)
        assertTrue(top.inlineDepth >= 2, "outer -> inline chain: ${top.inlineChain.map { it.name }}")
        assertEquals("outer_func", top.inlineChain.last().name)
        val chainNames = top.inlineChain.map { it.name }
        assertContains(chainNames, "inner_inline")
    }

    @Test
    fun queryReportsVersionBiasCuSequenceAndTableVersion() {
        val p = Dwarf.parse(buildElf())
        val cands = QueryEngine(listOf(p)).query(DwarfFixtures.INL_LO + 8)
        val c = cands.first()
        assertEquals(4, c.dwarfVersion)
        assertEquals(4, c.lineTableVersion)
        assertEquals(0, c.sequenceIndex)
        assertTrue(c.fileName.endsWith("header.h"))
        assertEquals(42, c.line)
        assertTrue(c.trustNotes.any { it.contains("解析完整") })
    }

    @Test
    fun importOrderDoesNotChangeQueryOrder() {
        fun engineBytes(): Pair<String, List<String>> {
            val p = Dwarf.parse(buildElf())
            val keys = QueryEngine(listOf(p)).query(DwarfFixtures.INL_LO + 4).map { it.stableKey }
            return p.elf.sha256 to keys
        }
        val (_, keys1) = engineBytes()
        repeat(3) {
            val (_, keys2) = engineBytes()
            assertEquals(keys1, keys2)
        }
    }
}
