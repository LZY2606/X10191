@file:Suppress("ArrayInDataClass")
package compass.fixture

import compass.fixture.DwarfFixture.AT_COMP_DIR
import compass.fixture.DwarfFixture.AT_ADDR_BASE
import compass.fixture.DwarfFixture.AT_DWO_ID
import compass.fixture.DwarfFixture.AT_DWO_NAME
import compass.fixture.DwarfFixture.AT_HIGH_PC
import compass.fixture.DwarfFixture.AT_LOW_PC
import compass.fixture.DwarfFixture.AT_NAME
import compass.fixture.DwarfFixture.AT_RANGES
import compass.fixture.DwarfFixture.AT_RNGLISTS_BASE
import compass.fixture.DwarfFixture.AT_STMT_LIST
import compass.fixture.DwarfFixture.AT_STR_OFFSETS_BASE
import compass.fixture.DwarfFixture.TAG_COMPILE_UNIT
import compass.fixture.DwarfFixture.TAG_SUBPROGRAM

data class DwoPair(val exe: ByteArray, val dwo: ByteArray)

object Fixtures5 {

    private fun a(attr: Int, form: Int, v: FixForm) = FixAttr(attr, form, v)

    /**
     * DWARF 5 split DWARF:
     *  exe (.debug_info): skeleton CU with DW_AT_dwo_id=0x1234, ranges for the function,
     *    .debug_addr (2 entries), .debug_rnglists with startx/endx
     *  dwo: split CU with same dwo_id, name + stmt_list, .debug_line.dwo
     */
    fun splitDwarf5(): DwoPair {
        // ---- main exe: skeleton CU ----
        // .debug_addr: header (length=12 -> 4+2+1+1+8+8=16 bytes total) then 2 entries
        val addrHdr = BytesBuilder().u32(12).u16(5).u8(8).u8(0).build()
        val addrData = addrHdr + BytesBuilder().u64(0x5000).u64(0x50c0).build()

        // .debug_rnglists: CU contribution
        // header: unit_length(rest), version=2, address_size=1, segment_selector_size=1,
        // offset_entry_count=1, offsets[0]=12 (relative to end of header incl. offset table),
        // then list at offset 12: startx_endx(0,1), end_of_list
        val listBody = BytesBuilder().u8(2).uleb(0).uleb(1).u8(0).build() // kind=2 startx_endx
        val hdrRest = BytesBuilder()
            .u16(5).u8(8).u8(0).u32(1).u32(listBody.size.toLong()).build()
        val rnglists = dwarf32Unit(hdrRest + listBody)

        val skeleton = FixDie(TAG_COMPILE_UNIT, children = listOf(
            FixDie(TAG_SUBPROGRAM, attrs = listOf(
                a(AT_RANGES, DwarfFixture.FORM_RNGLISTX, FixForm.Rnglistx(0))
            ))
        ), attrs = listOf(
            a(AT_DWO_ID, DwarfFixture.FORM_DATA8, FixForm.Data8(0x1234)),
            a(AT_DWO_NAME, DwarfFixture.FORM_STRING, FixForm.Str("main.dwo")),
            a(AT_ADDR_BASE, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0)),
            a(AT_RNGLISTS_BASE, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0))
        ))
        val skCompiled = compileUnit(skeleton)
        // v5 skeleton header: unit_length | version(2) unit_type=4 addr_size=1 abbrev_off dwo_id=8
        val skHdr = BytesBuilder().u16(5).u8(4).u8(8).u32(0).u64(0x1234).build()
        val skInfo = dwarf32Unit(skHdr + skCompiled.infoBody)


        val exeW = ElfWriter()
        exeW.addSection(".text", type = 1, flags = 6, addr = 0x5000, data = ByteArray(0x1000), addralign = 16)
        exeW.addSection(".debug_info", data = skInfo)
        exeW.addSection(".debug_abbrev", data = skCompiled.abbrev)
        exeW.addSection(".debug_addr", data = addrData)
        exeW.addSection(".debug_rnglists", data = rnglists)
        exeW.addLoadSegment(offset = 0x5000, vaddr = 0x5000, filesz = 0x1000)
        val exe = exeW.build()

        // ---- dwo companion: split CU ----
        val split = FixDie(TAG_COMPILE_UNIT, children = listOf(
            FixDie(TAG_SUBPROGRAM, attrs = listOf(
                a(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("splitfn")),
                a(AT_STMT_LIST, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0))
            ))
        ), attrs = listOf(
            a(AT_DWO_ID, DwarfFixture.FORM_DATA8, FixForm.Data8(0x1234)),
            a(AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("main.c")),
            a(AT_COMP_DIR, DwarfFixture.FORM_STRING, FixForm.Str("/work")),
            a(AT_STR_OFFSETS_BASE, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0))
        ))
        val spCompiled = compileUnit(split)
        val spHdr = BytesBuilder().u16(5).u8(5).u8(8).u32(0).u64(0x1234).build()
        val spInfo = dwarf32Unit(spHdr + spCompiled.infoBody)

        val dwoLine = run {
            val lp = LineProgramBuilder(5).v5File("main.c")
            lp.setAddress(0x5010).advanceLine(20).copy() // 0x5010 :21
                .advancePc(0x50).advanceLine(7).copy()   // 0x5060 :28
                .endSequence()
            lp.build()
        }

        val dwoW = ElfWriter()
        dwoW.addSection(".debug_info.dwo", data = spInfo)
        dwoW.addSection(".debug_abbrev.dwo", data = spCompiled.abbrev)
        dwoW.addSection(".debug_line.dwo", data = dwoLine)
        val dwo = dwoW.build()

        return DwoPair(exe, dwo)
    }
}
