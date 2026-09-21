@file:Suppress("ArrayInDataClass")
package compass.fixture

import compass.fixture.DwarfFixture.AT_CALL_FILE
import compass.fixture.DwarfFixture.AT_CALL_LINE
import compass.fixture.DwarfFixture.AT_COMP_DIR
import compass.fixture.DwarfFixture.AT_HIGH_PC
import compass.fixture.DwarfFixture.AT_LOW_PC
import compass.fixture.DwarfFixture.AT_NAME
import compass.fixture.DwarfFixture.AT_STMT_LIST
import compass.fixture.DwarfFixture.TAG_COMPILE_UNIT
import compass.fixture.DwarfFixture.TAG_INLINED
import compass.fixture.DwarfFixture.TAG_SUBPROGRAM

data class BuiltFixture(
    val elf: ByteArray,
    val dwo: ByteArray? = null,
    val addresses: Map<String, Long> = emptyMap()
)

private fun at(attr: Int, form: Int, v: FixForm) = FixAttr(attr, form, v)

object Fixtures {

    fun dwarf4(): BuiltFixture {
        val dieA = FixDie(TAG_INLINED, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("helper")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x2050)),
            at(AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x10)),
            at(AT_CALL_FILE, DwarfFixture.FORM_DATA2, FixForm.Data2(1)),
            at(AT_CALL_LINE, DwarfFixture.FORM_DATA2, FixForm.Data2(42))
        ))
        val dieB = FixDie(TAG_INLINED, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("helper")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x2080)),
            at(AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x10)),
            at(AT_CALL_FILE, DwarfFixture.FORM_DATA2, FixForm.Data2(1)),
            at(AT_CALL_LINE, DwarfFixture.FORM_DATA2, FixForm.Data2(55))
        ))
        val compute = FixDie(TAG_SUBPROGRAM, children = listOf(dieA, dieB), attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("compute")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x2000)),
            at(AT_HIGH_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x2100))
        ))
        val outer = FixDie(TAG_SUBPROGRAM, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("outer")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x1000)),
            at(AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x80))
        ))
        val hot = FixDie(TAG_SUBPROGRAM, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("hot")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x3000)),
            at(AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x40))
        ))
        val cold = FixDie(TAG_SUBPROGRAM, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("cold")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x3020)),
            at(AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x40))
        ))
        val point = FixDie(TAG_SUBPROGRAM, attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("point")),
            at(AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x4000))
        ))
        val cu = FixDie(TAG_COMPILE_UNIT, children = listOf(outer, compute, hot, cold, point), attrs = listOf(
            at(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("main.c")),
            at(AT_COMP_DIR, DwarfFixture.FORM_STRING, FixForm.Str("/work")),
            at(AT_STMT_LIST, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0))
        ))

        val compiled = compileUnit(cu)
        val info = dwarf32Unit(dwarf4CuHeader() + compiled.infoBody)
        val line = buildDwarf4Line()

        val w = ElfWriter()
        w.addSection(".text", type = 1, flags = 6, addr = 0x1000, data = ByteArray(0x4000), addralign = 16)
        w.addSection(".debug_info", data = info)
        w.addSection(".debug_abbrev", data = compiled.abbrev)
        w.addSection(".debug_line", data = line)
        w.addLoadSegment(offset = 0x1000, vaddr = 0x1000, filesz = 0x4000, memsz = 0x4000)
        return BuiltFixture(w.build(), addresses = mapOf(
            "insideOuter" to 0x1040,
            "insideCompute" to 0x2010,
            "insideInlineA" to 0x2058,
            "insideInlineB" to 0x2088,
            "overlap" to 0x3030,
            "point" to 0x4000,
            "nowhere" to 0x9999
        ))
    }

    private fun buildDwarf4Line(): ByteArray {
        // line_base=-5, line_range=14, initial line=1
        // special: adjusted = opAdvance*lineRange + (lineDelta - lineBase)
        // initial line=1; use advance_line for larger deltas, special opcodes for the combined
        // pc+line step. special: opcode = opcodeBase + opAdvance*lineRange + (lineDelta-lineBase)
        val lp = LineProgramBuilder(4).v4File("main.c").setAddress(0x1000)
        fun sp(opAdvance: Int, lineDelta: Int): Int =
            lp.opcodeBase + opAdvance * lp.lineRange + (lineDelta - lp.lineBase)
        lp.advanceLine(9).copy()   // 0x1000 :10
            .advanceLine(5).copy() // 0x1000 :15
            .advancePc(0x20).advanceLine(1).copy() // 0x1020 :16
            .endSequence()
            .setAddress(0x2000)
            .advanceLine(29).copy() // 0x2000 :30
            .setColumn(4).advanceLine(1)
            .advancePc(0x50).copy() // 0x2050 :31
            .advancePc(0x10).advanceLine(12).copy() // 0x2060 :43
            .advancePc(0x20).advanceLine(-10).copy() // 0x2080 :33
            .endSequence()
        return lp.build()
    }
}
