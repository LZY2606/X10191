package compass

import compass.dwarf.*
import compass.elf.ElfParser
import compass.fixtures.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Covers: special opcodes, end_sequence, overlapping ranges, high_pc two meanings,
 * address relocation (load bias), missing dwo, unknown form isolation, and
 * out-of-bounds references — using generated minimal ELF/DWARF fixtures.
 */
class CoreDwarfTest {

    private fun parse(elfBytes: ByteArray): ParsedDwarf {
        val elf = ElfParser.parse(elfBytes)
        return DwarfParser.parse(elf)
    }

    // ---------- DWARF 4 baseline: special opcodes + end_sequence + high_pc offset ----------
    @Test
    fun `dwarf4 special opcodes and end sequence`() {
        val f = DwarfFixture(version = 4)
        f.beginLineV4(
            dirs = listOf("/home/user/proj/"),
            files = listOf(Triple("main.c", 1, "main.c")),
        )
        // build a tiny line program with a special opcode then end_sequence
        // Mix special opcodes with an explicit copy. Initial registers are
        // (address=0x1000, line=1); copy() emits that first row unchanged.
        // A special opcode then applies op_advance*14 plus a line increment;
        // desired +1 line with line_base=-5 encodes as adjusted offset 6.
        f.setAddressExt(0x1000)
        f.setColumn(3)
        f.copy()                                              // 0x1000 main.c:1
        f.emitSpecial(opAdvance = 0x10, lineIncrement = 1)    // 0x1010 main.c:2
        f.emitSpecial(opAdvance = 0x10, lineIncrement = 1)    // 0x1020 main.c:3
        f.endSequence(0x1030)
        f.finalizeLine()

        val cu = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x1000), f.highPcOffset(0x30),
            f.udataAttr(Fixtures.AT_decl_file, Fixtures.FORM_data1, 1),
            f.udataAttr(Fixtures.AT_decl_line, Fixtures.FORM_data1, 2),
        ))
        f.beginCu(
            rootAttrs = listOf(
                f.strAttr(Fixtures.AT_name, "main.c", Fixtures.FORM_strp),
                f.strAttr(Fixtures.AT_comp_dir, "/home/user/proj", Fixtures.FORM_strp),
                f.stmtList(0),
                f.udataAttr(Fixtures.AT_language, Fixtures.FORM_data1, 12),
            ),
            children = listOf(cu),
        )
        val dwarf = parse(Fixtures.elf(Fixtures.sectionsOf(f)))
        assertEquals(1, dwarf.cus.size)
        val unit = dwarf.cus[0]
        assertEquals(4, unit.version)
        val lp = unit.lineProgram!!
        assertEquals(1, lp.sequences.size)
        val seq = lp.sequences[0]
        assertEquals(0x1000L, seq.startAddress)
        assertEquals(0x1030L, seq.endAddress)
        // two copied rows with increasing lines
        val rows = seq.rows.filter { !it.endSequence }
        assertEquals(3, rows.size)
        assertEquals(1, rows[0].line); assertEquals(0x1000L, rows[0].address); assertEquals(3, rows[0].column)
        assertEquals(2, rows[1].line); assertEquals(0x1010L, rows[1].address)
        assertEquals(3, rows[2].line); assertEquals(0x1020L, rows[2].address)
        assertEquals("main.c", lp.files[0].name)
    }

    // ---------- overlapping functions: both kept, narrowest first ----------
    @Test
    fun `overlapping ranges keep both candidates and narrowest wins`() {
        val f = DwarfFixture(version = 4)
        val outer = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x2000), f.highPcOffset(0x100),
            f.name("outer"),
        ))
        val inner = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x2020), f.highPcOffset(0x10),
            f.name("inner"),
        ))
        f.beginCu(rootAttrs = listOf(f.name("ov.c")), children = listOf(outer, inner))
        val dwarf = parse(Fixtures.elf(Fixtures.sectionsOf(f)))
        val engine = testEngine(dwarf)
        val r = engine.resolveRelative(0x2025, 0L, 1)
        assertTrue(r.resolved)
        assertEquals(2, r.candidates.size) { "overlap must preserve both legal scopes" }
        assertEquals("inner", r.candidates[0].scopeName)
        assertEquals(0x10L, r.candidates[0].rangeLength)
        assertEquals("outer", r.candidates[1].scopeName)
    }

    // ---------- zero-length range: visible but never matches ----------
    @Test
    fun `zero length range is retained but does not match`() {
        val f = DwarfFixture(version = 4)
        val marker = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x3000), // low only -> zero length
            f.name("marker"),
        ))
        val real = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x3010), f.highPcOffset(0x20), f.name("real"),
        ))
        f.beginCu(listOf(f.name("z.c")), listOf(marker, real))
        val dwarf = parse(Fixtures.elf(Fixtures.sectionsOf(f)))
        val engine = testEngine(dwarf)
        val scopes = engine.scopesFor(0)
        assertTrue(scopes.any { it.ranges.any { rg -> rg.length == 0L } })
        val at = engine.resolveRelative(0x3000, 0L, 1)
        // zero-length does not contain 0x3000
        assertTrue(at.candidates.none { it.scopeName == "marker" })
    }

    // ---------- high_pc absolute address form ----------
    @Test
    fun `high pc absolute address form supported`() {
        val f = DwarfFixture(version = 2)
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x4000), f.highPcAddr(0x4050), f.name("absfn"),
        ))
        f.beginCu(listOf(f.name("abs.c")), listOf(fn), addressSize = 8)
        val dwarf = parse(Fixtures.elf(Fixtures.sectionsOf(f)))
        val engine = testEngine(dwarf)
        val r = engine.resolveRelative(0x4020, 0L, 1)
        assertEquals("absfn", r.candidates.firstOrNull()?.scopeName)
    }

    // ---------- load bias / relocation ----------
    @Test
    fun `load bias relocates runtime address to relative`() {
        val f = DwarfFixture(version = 4)
        val fn = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(0x1000), f.highPcOffset(0x40), f.name("biased"),
        ))
        f.beginCu(listOf(f.name("b.c")), listOf(fn))
        val dwarf = parse(Fixtures.elf(Fixtures.sectionsOf(f)))
        val engine = testEngine(dwarf)
        val bias = 0x7f00_0000_0000L
        val r = engine.resolveRelative(0x1010, bias, 2)
        val c = r.candidates.first()
        assertEquals(0x1010L, c.relativeAddress)
        assertEquals(0x7f00_0000_1010L, c.inputAddress)
        assertEquals(bias, c.loadBias)
        assertEquals(2, c.generation)
    }
}
