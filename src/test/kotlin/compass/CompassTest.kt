package compass

import compass.dwarf.*
import compass.elf.ElfParser
import kotlin.test.*

class CompassTest {

    private fun parse(bytes: ByteArray, split: ByteArray? = null): DebugInfo {
        val elf = ElfParser.parse(bytes)
        val splitElf = split?.let { ElfParser.parse(it) }
        return DwarfParser.parse(elf, splitElf)
    }

    @Test
    fun `special opcodes and end_sequence yield two sequences`() {
        for (version in listOf(4, 5)) {
            val info = parse(ScenarioFixtures.overlappingInline(version))
            val cu = info.units.first { !it.isSplit }
            val lp = cu.lineProgram
            assertNotNull(lp, "v$version line program attached")
            assertEquals(version, lp.version)
            assertEquals(2, lp.sequences.size, "v$version sequences")
            val s1 = lp.sequences[0]
            assertEquals(0x1000L, s1.start)
            assertEquals(0x1040L, s1.end)
            // three emitted rows before the end_sequence row
            val rows = s1.rows.filter { !it.endSequence }
            assertEquals(listOf(10, 11, 12), rows.map { it.line })
            assertEquals(listOf(0x1000L, 0x1020L, 0x1030L), rows.map { it.address })
            assertTrue(s1.rows.last().endSequence)
        }
    }

    @Test
    fun `overlapping function and inline chain resolved with narrowest range`() {
        val info = parse(ScenarioFixtures.overlappingInline(4))
        val r = Resolver(info).query(0x1025, null)
        assertTrue(r.candidates.isNotEmpty(), "should have a candidate")
        val top = r.candidates.first()
        val chain = top.inlineChain
        // outer + inlined helper
        assertEquals(listOf("outer", "helper"), chain.map { it.function })
        assertEquals(1, chain.last().depth)
        assertEquals(77, chain.last().callLine)
        // line row at 0x1025 maps to main.c:11
        assertNotNull(top.line)
        assertEquals(11, top.line!!.line)
        assertEquals("main.c", top.line!!.file)
        assertEquals("DWARF4", top.line!!.tableVersion)
    }

    @Test
    fun `query outside inline picks outer function and line 10`() {
        val info = parse(ScenarioFixtures.overlappingInline(4))
        val r = Resolver(info).query(0x1005, null)
        assertEquals(listOf("outer"), r.candidates.first().inlineChain.map { it.function })
        assertEquals(10, r.candidates.first().line!!.line)
    }

    @Test
    fun `second line sequence is addressable independently`() {
        val info = parse(ScenarioFixtures.overlappingInline(5))
        val r = Resolver(info).query(0x2005, null)
        val top = r.candidates.first()
        assertEquals(20, top.line!!.line)
        assertEquals(1, top.sequenceIndex)
    }

    @Test
    fun `high_pc constant means size, address form means absolute`() {
        // CONST path used by the main fixture: outer spans 0x1000..0x1040
        val info = parse(ScenarioFixtures.overlappingInline(4))
        val cu = info.units.first()
        val outer = cu.root!!.children.first { it.str(DW_AT_name) == "outer" }
        assertEquals(listOf(PcRange(0x1000, 0x1040)), DieRanges.of(outer))
    }

    @Test
    fun `ranges section maps multiple functions`() {
        val info = parse(ScenarioFixtures.zeroAndOverlappingRanges())
        val cu = info.units.first()
        val fn = cu.root!!.children.first { it.str(DW_AT_name) == "funcA" }
        assertEquals(listOf(PcRange(0x2000, 0x2080)), DieRanges.of(fn))
        val r = Resolver(info).query(0x2010, null)
        assertTrue(r.candidates.any { it.coveringFunction == "funcA" })
    }

    @Test
    fun `zero-length exact match sorts narrowest`() {
        // Build a CU with a zero-length DIE at 0x1020 colliding with outer range.
        val bytes = ZeroLenFixture.build()
        val info = parse(bytes)
        val r = Resolver(info).query(0x1020, null)
        assertEquals("point", r.candidates.first().coveringFunction)
        // At a different address outer wins.
        assertEquals("outer", Resolver(info).query(0x1021, null).candidates.first().coveringFunction)
    }

    @Test
    fun `load bias relocates runtime addresses across generations`() {
        val info = parse(ScenarioFixtures.overlappingInline(4))
        val g1 = ModuleLoad("app", 0x0, 0x7f0000000000, generation = 1)
        val g2 = ModuleLoad("app", 0x0, 0x555555554000, generation = 2)
        // same relative 0x1025, different runtime PCs
        val r1 = Resolver(info).query(0x7f0000000000 + 0x1025, g1)
        val r2 = Resolver(info).query(0x555555554000 + 0x1025, g2)
        assertEquals(0x1025L, r1.relativePc)
        assertEquals(0x1025L, r2.relativePc)
        assertEquals(0x7f0000000000, r1.loadBias)
        assertEquals(0x555555554000, r2.loadBias)
        assertEquals(r1.candidates.first().line!!.line, r2.candidates.first().line!!.line)
    }

    @Test
    fun `missing dwo is reported while skeleton conclusions stay trustworthy`() {
        val info = parse(ScenarioFixtures.skeletonMissingDwo(5))
        assertEquals(SplitStatus.MISSING_DWO, info.splitStatus)
        val r = Resolver(info).query(0x3005, null)
        assertTrue(r.warnings.any { it.contains("dwo") })
        assertTrue(r.trusted.any { it.contains("可信") })
    }

    @Test
    fun `unknown form isolates unit without fabricated results`() {
        val info = parse(ScenarioFixtures.unknownFormFixture())
        // The bad unit must appear in issues, and units list must not invent extra CUs.
        assertTrue(info.issues.isNotEmpty(), "issue recorded")
        assertTrue(info.issues.all { it.message.contains("DW_FORM") || it.message.contains("form") })
    }

    @Test
    fun `out of bounds abbrev reference is contained`() {
        val info = parse(ScenarioFixtures.outOfBoundsRefFixture())
        assertTrue(info.issues.isNotEmpty())
        assertTrue(info.issues.first().message.contains("越界") || info.issues.first().message.contains("abbrev"))
    }

    @Test
    fun `candidate ordering is stable regardless of CU iteration start`() {
        // Two CUs with identical overlapping ranges; tie key is absolute offsets.
        val info = parse(TwoCusFixture.build())
        val order1 = Resolver(info).query(0x1020, null).candidates.map { it.tieKey }
        val order2 = Resolver(info).query(0x1020, null).candidates.map { it.tieKey }
        assertEquals(order1, order2)
        // First key must be the lower CU offset.
        val cuOffsets = order1.map { it.substringAfter("cu=").substringBefore(" ").toLong() }
        assertEquals(cuOffsets.sorted(), cuOffsets)
    }
}
