package compass

import compass.dwarf.*
import compass.elf.ElfParser
import compass.fixtures.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class AdvancedDwarfTest {

    private fun parse(f: DwarfFixture) =
        DwarfParser.parse(ElfParser.parse(Fixtures.elf(Fixtures.sectionsOf(f))))

    @Test
    fun `dwarf4 debug_ranges discontiguous function`() {
        val f = DwarfFixture(version = 4)
        val rangeOff = f.v4Range(listOf(0x10L to 0x20L, 0x40L to 0x50L))
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x5000), f.rangesSecOffset(rangeOff), f.name("pieces"),
        ))
        f.beginCu(listOf(f.name("p.c")), listOf(fn))
        val d = parse(f)
        val engine = testEngine(d)
        assertEquals("pieces", engine.resolveRelative(0x5010, 0L, 1).candidates.firstOrNull()?.scopeName)
        assertEquals("pieces", engine.resolveRelative(0x5040, 0L, 1).candidates.firstOrNull()?.scopeName)
        assertNull(engine.resolveRelative(0x5030, 0L, 1).candidates.firstOrNull())
    }

    @Test
    fun `dwarf5 rnglists with addrx and strx`() {
        val f = DwarfFixture(version = 5)
        val addrBase = f.addrv5(listOf(0x6000, 0x6100))
        val rngBase = f.rnglistsV5(startxEndx = listOf(0 to 1))
        // CU root: name via strx, addr_base; subprogram via DW_AT_ranges sec_offset
        val cuName = f.attr(Fixtures.AT_name, Fixtures.FORM_strx) { it.uleb(0) }
        // prepare str_offsets section with one entry pointing into .debug_str
        val strOff = f.str.bytes().size.toLong()
        f.str.cstr("v5cu.c")
        // header for .debug_str_offsets
        val so = compass.fixtures.Bin()
        so.u32(8L + 4) // length = 8-byte header + one 4-byte entry
        so.u16(5); so.u16(0) // version + padding
        so.u32(strOff)
        f.strOffsets.bytes(so.bytes())
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.rangesSecOffset(rngBase), f.name("v5fn"),
        ))
        f.beginCu(
            rootAttrs = listOf(
                cuName,
                f.udataAttr(Fixtures.AT_addr_base, Fixtures.FORM_data4, addrBase),
                f.udataAttr(Fixtures.AT_str_offsets_base, Fixtures.FORM_data4, 8),
            ),
            children = listOf(fn), unitType = 0x01,
        )
        val d = parse(f)
        assertEquals(5, d.cus[0].version)
        assertEquals("v5cu.c", d.cus[0].root.attr(DW.AT_name).let { (it as AttrValue.Str).value })
        val engine = testEngine(d)
        val r = engine.resolveRelative(0x6050, 0L, 1)
        assertEquals("v5fn", r.candidates.firstOrNull()?.scopeName)
        assertEquals("DWARF5", r.candidates.first().tableVersion.substringBefore('/'))
    }

    @Test
    fun `inline call chain reported from innermost frame`() {
        val f = DwarfFixture(version = 4)
        val inner = f.die(Fixtures.TAG_inlined_subroutine, listOf(
            f.lowPc(0x7010), f.highPcOffset(0x10),
            f.name("callee"),
            f.udataAttr(Fixtures.AT_call_file, Fixtures.FORM_data1, 1),
            f.udataAttr(Fixtures.AT_call_line, Fixtures.FORM_data1, 7),
        ))
        val outer = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x7000), f.highPcOffset(0x40), f.name("caller"),
        ), children = listOf(inner))
        f.beginCu(
            rootAttrs = listOf(f.name("inl.c"), f.strAttr(Fixtures.AT_comp_dir, "/x", Fixtures.FORM_strp)),
            children = listOf(outer),
        )
        val d = parse(f)
        val engine = testEngine(d)
        val r = engine.resolveRelative(0x7018, 0L, 1)
        val c = r.candidates.first()
        assertEquals("callee", c.scopeName)
        assertEquals(1, c.inlineDepth)
        assertEquals(listOf("caller", "callee"), c.inlineChain.map { it.name })
        assertEquals(7, c.inlineChain.last().callLine)
    }

    @Test
    fun `missing dwo is reported but skeleton ranges and lines stay usable`() {
        val f = DwarfFixture(version = 5)
        // v5 line program so the skeleton has line rows
        f.beginLineV5(dirs = listOf("/p/"), files = listOf("s.c" to 0))
        f.emitSpecial(0, 1); f.copy(); f.endSequence(0x8030)
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x8000), f.highPcOffset(0x30), f.name("skelfn"),
        ))
        f.beginCu(
            rootAttrs = listOf(
                f.strAttr(Fixtures.AT_name, "s.c", 0x1f, lineStrSection = true),
                f.strAttr(Fixtures.AT_dwo_name, "s.dwo", Fixtures.FORM_strp),
                f.stmtList(0),
            ),
            children = listOf(fn), unitType = 0x04, // skeleton
        )
        val d = parse(f)
        val cu = d.cus[0]
        assertNotNull(cu.dwoName)
        assertTrue(cu.warnings.any { it.contains("dwo") })
        // line program still parsed from the skeleton
        assertNotNull(cu.lineProgram)
        val engine = testEngine(d)
        val r = engine.resolveRelative(0x8010, 0L, 1)
        assertTrue(r.resolved)
        assertTrue(r.candidates.first().dwoMissing)
    }

    @Test
    fun `unknown form isolates the unit but keeps header trustworthy`() {
        val f = DwarfFixture(version = 4)
        // craft abbrev referencing a bogus form 0x7777 inside the CU
        val bogus = f.attr(0x3456, 0x7777) { }
        val weird = f.die(Fixtures.TAG_subprogram, listOf(bogus, f.name("weird")))
        f.beginCu(listOf(f.name("weird.c"), f.stmtList(0)), listOf(weird))
        val d = parse(f)
        val cu = d.cus[0]
        assertTrue(cu.warnings.any { it.contains("未知 form") })
        // root attributes (CU name) survive
        assertEquals("weird.c", (cu.root.attr(DW.AT_name) as AttrValue.Str).value)
    }

    @Test
    fun `out of bounds reference does not crash and yields no false scope`() {
        val f = DwarfFixture(version = 4)
        // subprogram with an abstract_origin ref4 pointing far beyond the section
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x9000), f.highPcOffset(0x10),
            f.refAttr(Fixtures.AT_abstract_origin, Fixtures.FORM_ref4, 0xffffff00),
        ))
        f.beginCu(listOf(f.name("oob.c")), listOf(fn))
        val d = parse(f)
        val engine = testEngine(d)
        // must not throw; no name chain available, address still resolves by range
        val r = engine.resolveRelative(0x9005, 0L, 1)
        assertTrue(r.resolved)
    }

    @Test
    fun `multiple line sequences are indexed separately`() {
        val f = DwarfFixture(version = 4)
        f.beginLineV4(dirs = listOf("/d/"), files = listOf(Triple("a.c", 1, "a.c"), Triple("b.c", 1, "b.c")))
        // sequence 0
        f.setAddressExt(0xa000)
        f.setFile(1); f.setLine(1); f.copy(); f.endSequence(0xa010)
        // sequence 1 via set_address
        f.setAddressExt(0xb000)
        f.setFile(2); f.setLine(1); f.copy(); f.endSequence(0xb020)
        f.beginCu(listOf(f.name("multi.c"), f.stmtList(0)), emptyList())
        val d = parse(f)
        val seqs = d.cus[0].lineProgram!!.sequences
        assertEquals(2, seqs.size)
        assertEquals(0xa000L, seqs[0].startAddress)
        assertEquals(0xb000L, seqs[1].startAddress)
    }
}
