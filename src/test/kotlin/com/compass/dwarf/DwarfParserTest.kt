package com.compass.dwarf

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DwarfParserTest {
    @Test
    fun parsesSpecialOpcodesAndMultipleEndSequences() {
        val line = Fixtures.v4Line(0x401000, 0x402000)
        val info = Fixtures.v4Info({ u8(2).text("main").u32(0x401000).u32(0x402010) }, Fixtures.simpleAbbrev(), 0)
        val doc = parse(info, Fixtures.simpleAbbrev(), ".debug_line" to line)
        val sequences = doc.compilationUnits.single().lineProgram!!.sequences
        assertEquals(2, sequences.size)
        assertEquals(0x401000L, sequences[0].startAddress)
        assertEquals(0x402000L, sequences[1].startAddress)
        assertTrue(sequences.all { it.rows.last().endSequence })
    }

    @Test
    fun parsesHighPcConstantZeroLengthAndOverlappingRanges() {
        val line = Fixtures.v4Line(0x401000)
        val abbrev = Fixtures.simpleAbbrev(Fixtures.FORM_ADDR)
        val info = Fixtures.v4Info({
            u8(2).text("outer").u32(0x401000).u32(0x401020)
            u8(2).text("narrow").u32(0x401010).u32(0x401010)
        }, abbrev, 0)
        val doc = parse(info, abbrev, ".debug_line" to line)
        val ranges = doc.compilationUnits.single().ranges
        assertEquals(listOf("outer", "narrow"), ranges.map { it.name })
        assertEquals(0x20, ranges[0].width)
        assertTrue(ranges[1].zeroLength)
        val explanation = AddressResolver.explain(doc, QueryAddress(0, 0x401010), 0)
        assertEquals(2, explanation.allCandidates.size)
        assertEquals("narrow", explanation.allCandidates.first().name)
    }

    @Test
    fun parsesHighPcAddressMeaning() {
        val info = Fixtures.v4Info({ u8(2).text("main").u32(0x500).u32(0x510) }, Fixtures.simpleAbbrev(), 0)
        val doc = parse(info, Fixtures.simpleAbbrev())
        val range = doc.compilationUnits.single().ranges.single()
        assertEquals(0x500L, range.start)
        assertEquals(0x510L, range.end)
    }

    @Test
    fun preservesInlineChainAndCallSite() {
        val line = Fixtures.v4Line(0x401000)
        val abbrev = Fixtures.inlineAbbrev()
        val info = Fixtures.v4Info({
            u8(2).text("helper")
            u8(3)
            u8(4).u32(0x0f).u32(0x401010).u8(8).u8(1).u8(42)
            u8(0)
        }, abbrev, 0)
        val doc = parse(info, abbrev, ".debug_line" to line)
        val explanation = AddressResolver.explain(doc, QueryAddress(0, 0x401014), 0)
        assertEquals("helper", explanation.inlineChain.single().name)
        assertEquals(42, explanation.inlineChain.single().callLine)
        assertEquals(1, explanation.inlineChain.single().inlineDepth)
    }

    @Test
    fun parsesDwarf5LineProgram() {
        val line = Fixtures.v5Line(0x401000)
        val info = Fixtures.v5Info({ u8(2).text("main").u32(0x401000).u32(0x401010) }, 0)
        val doc = parse(info, Fixtures.simpleAbbrev(), ".debug_line" to line, ".debug_line_str" to ByteBuilder().u8(0).text("main.c").build())
        val program = doc.compilationUnits.single().lineProgram!!
        assertEquals(5, program.version)
        assertContains(program.files.single().name, "main.c")
    }

    @Test
    fun reportsMissingDwoButStillTrustsSkeletonLineResult() {
        val abbrev = Fixtures.abbrev({
            uleb(Fixtures.TAG_CU.toLong()); u8(1)
            uleb(Fixtures.AT_NAME.toLong()); uleb(Fixtures.FORM_STRING.toLong())
            uleb(Fixtures.AT_COMP_DIR.toLong()); uleb(Fixtures.FORM_STRING.toLong())
            uleb(Fixtures.AT_STMT_LIST.toLong()); uleb(Fixtures.FORM_SEC_OFFSET.toLong())
            uleb(Fixtures.AT_DWO_NAME.toLong()); uleb(Fixtures.FORM_STRING.toLong())
            uleb(Fixtures.AT_DWO_ID.toLong()); uleb(Fixtures.FORM_DATA8.toLong())
            uleb(0); uleb(0)
        })
        val line = Fixtures.v4Line(0x401000)
        val info = Fixtures.v4Info({ text("missing.dwo").u64(99) }, abbrev, 0)
        val doc = parse(info, abbrev, ".debug_line" to line)
        val explanation = AddressResolver.explain(doc, QueryAddress(0, 0x401001), 0)
        assertEquals("main.c", explanation.file)
        assertContains(explanation.warnings.joinToString("\n"), "Split DWARF")
        assertContains(explanation.trusted.joinToString("\n"), "line data remain usable")
    }

    @Test
    fun isolatesUnknownFormWithoutProducingPseudoDies() {
        val abbrev = Fixtures.abbrev({
            uleb(Fixtures.TAG_CU.toLong()); u8(0)
            uleb(Fixtures.AT_NAME.toLong()); uleb(0x99)
            uleb(0); uleb(0)
        })
        val info = Fixtures.v4Info({ }, abbrev, 0)
        val doc = parse(info, abbrev)
        assertTrue(doc.compilationUnits.isEmpty())
        assertContains(doc.warnings.joinToString("\n"), "Unknown DWARF form")
    }

    @Test
    fun toleratesOutOfBoundsAbstractOriginAndKeepsLineResult() {
        val line = Fixtures.v4Line(0x401000)
        val abbrev = Fixtures.inlineAbbrev()
        val info = Fixtures.v4Info({
            u8(2).text("helper")
            u8(3)
            u8(4).u32(0xfffffff0).u32(0x401010).u8(8).u8(1).u8(42)
            u8(0)
        }, abbrev, 0)
        val doc = parse(info, abbrev, ".debug_line" to line)
        val explanation = AddressResolver.explain(doc, QueryAddress(0, 0x401001), 0)
        assertEquals("main.c", explanation.file)
        assertNotNull(explanation.sequenceStart)
    }

    private fun parse(info: ByteArray, abbrev: ByteArray, vararg extra: Pair<String, ByteArray>): DebugDocument {
        val sections = mutableMapOf(".debug_info" to info, ".debug_abbrev" to abbrev)
        sections.putAll(extra)
        return DebugFileParser.parse(Fixtures.elf(sections))
    }
}
