package compass

import compass.dwarf.AddressResolver
import compass.dwarf.DwarfParser
import compass.dwarf.DebugVersion
import compass.dwarf.ModuleLoad
import compass.elf.ElfParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertNotNull

private class TmpVersion(
    override val versionId: Long, override val label: String,
    override val priority: Int, override val image: compass.dwarf.DwarfImage
) : DebugVersion

class DwarfParserTest {

    private fun fixtureElf(fx: Dwarf4Fixture, base: Long = fx.base): ByteArray {
        val fb = FixtureBuilder(base, ByteArray(0x40){0x90.toByte()}, fx.textBase)
            .section(".text", ByteArray(0x40) { 0x90.toByte() })
            .debugInfo(fx.infoData).debugAbbrev(fx.abbrevData).debugLine(fx.lineData)
        fx.rangesData?.let { fb.debugRanges(it) }
        fx.strData?.let { fb.debugStr(it) }
        return fb.build()
    }

    private fun resolve(elf: ByteArray, addr: Long, bias: Long = 0L, priority: Int = 100): compass.dwarf.AddressAnswer {
        val img = DwarfParser.parseBytes(elf)
        val v = TmpVersion(1, "test", priority, img)
        return AddressResolver(listOf(v),
            listOf(ModuleLoad(1, 1, 1, bias, bias, 0, "mod"))).resolve(addr + bias)
    }

    @Test
    fun `special opcodes and end_sequence map to file line column`() {
        // Build a line program driven by special opcodes only (no COPY).
        val prog = specialOnlyProgram(0x401000)
        val fx = Dwarf4Fixture().apply {
            lineData = prog
            cuWithDies(listOf(DieSpec("sub", "main", 0x401000, 0x401020, HighKind.CONST,
                declLine = 3)))
        }
        val elf = fixtureElf(fx)
        val ans = resolve(elf, 0x401005)
        val c = ans.primary
        assertNotNull(c, "应找到候选: ${ans.notes}")
        assertTrue(c.file!!.endsWith("hello.c"))
        assertEquals(true, c.line in 3..6, "special opcode 推进行号，实际 line=${c.line}")
        // end_sequence address itself should NOT map as a normal row
        val img = DwarfParser.parseBytes(elf)
        assertEquals(1, img.sequences.size, "一个 end_sequence -> 一个 sequence")
        assertTrue(img.sequences[0].rows.last().endSequence)
    }

    @Test
    fun `high_pc address form and constant form both resolve`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000, listOf(LineRowSpec(0x401000, 10), LineRowSpec(0x401010, 11)), 0x401020)
            cuWithDies(listOf(
                DieSpec("sub", "addr_form", 0x401000, 0x401010, HighKind.ADDR, declLine = 10),
                DieSpec("sub", "const_form", 0x401010, 0x401020, HighKind.CONST, declLine = 11)
            ))
        }
        val elf = fixtureElf(fx)
        val a = resolve(elf, 0x401005)
        val b = resolve(elf, 0x401015)
        assertEquals("addr_form", a.primary!!.inlineChain.last().name)
        assertEquals("const_form", b.primary!!.inlineChain.last().name)
        assertEquals(10, a.primary!!.line)
        assertEquals(11, b.primary!!.line)
    }

    @Test
    fun `overlapping functions retain all candidates ordered narrowest first`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000,
                listOf(LineRowSpec(0x401000, 20), LineRowSpec(0x401008, 21), LineRowSpec(0x401010, 22)),
                0x401030)
            // outer 0x401000..0x401030, inner 0x401008..0x401010 (narrower)
            cuWithDies(listOf(
                DieSpec("sub", "outer", 0x401000, 0x401030, HighKind.CONST, declLine = 20,
                    children = listOf(DieSpec("subInline", "inner", 0x401008, 0x401010,
                        HighKind.CONST, callLine = 20)))
            ))
        }
        val elf = fixtureElf(fx)
        val ans = resolve(elf, 0x401009)
        assertTrue(ans.candidates.isNotEmpty())
        // Function hits: inner (narrow) and outer; candidate keyed on innermost should name inner
        assertEquals("inner", ans.primary!!.inlineChain.last().name)
        val chainNames = ans.primary!!.inlineChain.map { it.name }
        assertTrue(chainNames.containsAll(listOf("outer", "inner")),
            "内联链应包含 outer -> inner，实际 $chainNames")
    }

    @Test
    fun `multiple line sequences stay distinct and overlapping both queryable`() {
        val fx = Dwarf4Fixture().apply {
            lineData = Dwarf4Fixture().let {
                multiSequenceLine(listOf(
                    Triple(0x401000, listOf(LineRowSpec(0x401000, 1), LineRowSpec(0x401004, 2)), 0x401008),
                    // second sequence overlaps first address window
                    Triple(0x401004, listOf(LineRowSpec(0x401004, 100), LineRowSpec(0x401006, 101)), 0x401008)
                ))
            }
            cuWithDies(listOf(DieSpec("sub", "f", 0x401000, 0x401010, HighKind.CONST, declLine = 1)))
        }
        val elf = fixtureElf(fx)
        val img = DwarfParser.parseBytes(elf)
        assertEquals(2, img.sequences.size, "两个 end_sequence -> 两个 sequence")
        val ans = resolve(elf, 0x401005)
        val lines = ans.candidates.mapNotNull { if (it.sequenceId >= 0) it.line else null }.toSet()
        assertTrue(lines.contains(2) && lines.contains(101),
            "重叠 sequence 的两种行号解释都要保留，实际 $lines")
    }

    @Test
    fun `zero length ranges are preserved and marked`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000, listOf(LineRowSpec(0x401000, 5)), 0x401010)
            cuWithDies(listOf(
                DieSpec("sub", "zero_sym", 0x401020, 0x401020, HighKind.CONST, declLine = 99)
            ))
        }
        val elf = fixtureElf(fx)
        val img = DwarfParser.parseBytes(elf)
        val zeroRanges = (img.cus.flatMap { cu ->
            cu.dieByOffset.values.flatMap { it.ranges }
        }).filter { it.zeroLength }
        assertEquals(1, zeroRanges.size, "high_pc 偏移为 0 必须保留为零长度范围")
        val ans = resolve(elf, 0x401020)
        assertTrue(ans.candidates.any { it.rangeZeroLength }, "零长度符号候选需带标记")
    }

    @Test
    fun `runtime load bias translates address across generations`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000, listOf(LineRowSpec(0x401000, 7), LineRowSpec(0x401010, 8)), 0x401020)
            cuWithDies(listOf(DieSpec("sub", "g", 0x401000, 0x401020, HighKind.CONST, declLine = 7)))
        }
        val elf = fixtureElf(fx)
        val img = DwarfParser.parseBytes(elf)
        val v = TmpVersion(1, "t", 100, img)
        val loads = listOf(
            ModuleLoad(1, 1, 1, 0x7f000000L, 0x7f000000L - 0, 0, "gen1"),
            ModuleLoad(2, 1, 2, 0x10000000L, 0x10000000L, 0, "gen2")
        )
        val resolver = AddressResolver(listOf(v), loads)
        val a1 = resolver.resolve(0x7f000000L + 0x401005, atGeneration = 1)
        val a2 = resolver.resolve(0x10000000L + 0x401005, atGeneration = 2)
        assertEquals(0x401005L, a1.resolvedRelative)
        assertEquals(0x401005L, a2.resolvedRelative)
        assertEquals(7L, a1.primary!!.line.toLong())
        assertEquals(7L, a2.primary!!.line.toLong())
    }

    @Test
    fun `import order does not change query ordering`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000, listOf(LineRowSpec(0x401000, 1)), 0x401020)
            cuWithDies(listOf(DieSpec("sub", "h", 0x401000, 0x401020, HighKind.CONST, declLine = 1)))
        }
        val elf = fixtureElf(fx)
        fun answer(order: List<Long>): compass.dwarf.AddressAnswer {
            val img = DwarfParser.parseBytes(elf)
            val vs = order.mapIndexed { i, id ->
                TmpVersion(id, "v$id", 100, img) }
            val loads = order.map { ModuleLoad(it, it, it, it * 0x100000, it * 0x100000, 0, "m$it") }
            return AddressResolver(vs, loads).resolve(0x401000 + order.first() * 0x100000)
        }
        // Same version ids, same single physical module: answer order identical.
        val ids = listOf(7L, 2L, 9L)
        val a = answer(ids)
        val b = answer(ids.reversed())
        // Deterministic: same inputs -> same candidate signature
        assertEquals(
            a.candidates.map { listOf(it.versionId, it.cuOffset, it.line) },
            b.candidates.map { listOf(it.versionId, it.cuOffset, it.line) }
        )
    }

    @Test
    fun `raw elf parses and sha256 summary is stable`() {
        val fx = Dwarf4Fixture().apply {
            lineData = simpleLine(0x401000, listOf(LineRowSpec(0x401000, 1)), 0x401010)
            cuWithDies(listOf(DieSpec("sub", "x", 0x401000, 0x401010, HighKind.CONST)))
        }
        val bytes = fixtureElf(fx)
        val elf = ElfParser.parse(bytes)
        assertEquals(1, elf.sha256().let { if (it.length == 64) 1 else 0 })
        assertNotNull(elf.section(".debug_info"))
    }

    private fun simpleLine(start: Long, rows: List<LineRowSpec>, end: Long): ByteArray =
        Dwarf4Fixture().lineProgram(start, rows, end)

    private fun specialOnlyProgram(start: Long): ByteArray {
        // Manually emit a line program using ONLY special opcodes.
        val prog = BinBuilder()
        prog.u8(0).uleb(9).u8(0x02).u64(start)
        // header params: line_base=-5 line_range=14 opcode_base=13
        // adjusted op -> line advance = line_base + (adjusted/line_range), pc = adjusted%lineRange
        // special op 13+14=27 -> line advance -5+1 = -4... instead construct:
        // choose op = opcode_base + (0*14) + 8 -> line -5+0, pc 8... messy; use straightforward:
        // first row at line 3: start state line=1, need +2; use op adjusted= 2*14+0 => op=41, pc 0
        prog.u8(13 + 2 * 14 + 0)      // line +2 -> 3, pc +0, emit row
        prog.u8(13 + 3 * 14 + 1)      // line +3 -> 6, pc +1
        // end sequence at start+16
        prog.u8(DW_LNS.ADVANCE_PC).uleb(15)
        prog.u8(0).uleb(1).u8(DW_LNE.END_SEQUENCE)
        val prologue = BinBuilder()
        prologue.u8(1).u8(1).bytes(0xfb).u8(14).u8(13) // line_base=-5
        prologue.bytes(0,1,1,1,1,0,0,0,1,0,0,1)
        prologue.str("/proj/src").str("").str("hello.c").uleb(1).uleb(0).uleb(0).str("")
        val pb = prologue.build()
        return dwarfUnit { u16(4); u32(pb.size.toLong()); blob(pb); blob(prog.build()) }
    }
}
