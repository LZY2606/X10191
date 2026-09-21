package compass

import compass.dwarf.*

/** Complete tiny DWARF4 + DWARF5 ELF fixtures assembled from real section bytes. */
object ScenarioFixtures {

    const val ABI_ADDR_SIZE = 8

    /**
     * A single CU with:
     *   - abstract inlined root "helper" (DW_AT_inline)
     *   - concrete subprogram "outer" [0x1000..0x1040)
     *   - inlined_subroutine (origin -> helper) at [0x1020..0x1030), call_line 77
     * line program covers two sequences.
     */
    fun overlappingInline(version: Int): ByteArray {
        val fb = FixtureBuilder()
        val abbrev = DwarfFixtures.abbrevSet(
            version,
            AbbrevConfig(
                highPcForm = HighPcForm.CONST,
                includeInlined = true,
                includeAbstractRoot = true,
                abstractInline = false,
                subprogramChildren = true
            )
        )
        fb.section(".debug_abbrev", abbrev)

        // .debug_line: build first, know its offset (it starts section at 0).
        val line = lineProgram(version)
        fb.section(".debug_line", line)

        // .debug_info
        val info = infoUnit(version)
        fb.section(".debug_info", info)
        fb.section(".text", ByteArray(0x2000) { 0xc3.toByte() })
        return fb.build()
    }

    /** DWARF4 ranges section: two overlapping function ranges incl. zero length. */
    fun zeroAndOverlappingRanges(): ByteArray {
        val fb = FixtureBuilder()
        val abbrev = DwarfFixtures.abbrevSet(
            4, AbbrevConfig(highPcForm = HighPcForm.RANGES, subprogramChildren = false)
        )
        fb.section(".debug_abbrev", abbrev)
        val ranges = ByteArrayBuilder().apply {
            // function A: [0x2000..0x2080)
            u64(0x2000); u64(0x2080)
            u64(0); u64(0)
        }.build()
        fb.section(".debug_ranges", ranges)
        val line = lineProgram(4)
        fb.section(".debug_line", line)
        fb.section(".debug_info", rangesInfoDwarf4())
        fb.section(".text", ByteArray(0x3000) { 0xc3.toByte() })
        return fb.build()
    }

    /** Skeleton referencing a .dwo that is not provided. */
    fun skeletonMissingDwo(version: Int = 5): ByteArray {
        val fb = FixtureBuilder()
        val abbrev = DwarfFixtures.abbrevSet(
            version, AbbrevConfig(highPcForm = HighPcForm.CONST, dwoName = true)
        )
        fb.section(".debug_abbrev", abbrev)
        fb.section(".debug_line", lineProgram(version))
        fb.section(".debug_info", skeletonInfo(version))
        return fb.build()
    }

    /** A CU whose DIE contains an unknown form; must be isolated, no fabricated DIEs. */
    fun unknownFormFixture(): ByteArray {
        val fb = FixtureBuilder()
        fb.section(".debug_abbrev", DwarfFixtures.abbrevSet(4, AbbrevConfig(unknownForm = true)))
        // Root abbrev code1 needs a subprogram child referencing code 5. Build info manually.
        fb.section(".debug_info", unknownFormInfo())
        return fb.build()
    }

    /** CU header claims a huge length / abbrev offset out of bounds. */
    fun outOfBoundsRefFixture(): ByteArray {
        val fb = FixtureBuilder()
        fb.section(".debug_abbrev", byteArrayOf(0))
        fb.section(".debug_info", outOfBoundsInfo())
        return fb.build()
    }

    // ---- .debug_info encodings ----

    private fun infoUnit(version: Int): ByteArray {
        // DW_FORM_ref4 offsets are relative to the first byte of the CU header.
        val headerSize = if (version >= 5) 23 else 11
        val body = ByteArrayBuilder()
        val dieBase = headerSize // CU-relative offset where DIEs begin
        fun cuOff() = dieBase + body.size()

        body.uleb(1)
        body.u32(0) // stmt_list
        body.cstr("main.c"); body.cstr("/proj/src")

        val abstractOff = cuOff()
        body.uleb(4); body.cstr("helper"); body.u8(1)

        body.uleb(2); body.cstr("outer"); body.u64(0x1000); body.u32(0x40)
        body.uleb(3); body.u32(abstractOff.toLong())
        body.u64(0x1020); body.u32(0x10); body.u16(77)
        body.uleb(0) // end outer children
        body.uleb(0) // end CU children
        return wrapUnit(version, body.build())
    }

    private fun rangesInfoDwarf4(): ByteArray {
        val body = ByteArrayBuilder().apply {
            uleb(1); u32(0); cstr("ranges.c"); cstr("/p")
            uleb(2); cstr("funcA")
            u32(0) // DW_AT_ranges offset 0
            uleb(0); uleb(0)
        }.build()
        return wrapUnit(4, body)
    }

    private fun skeletonInfo(version: Int): ByteArray {
        val body = ByteArrayBuilder().apply {
            uleb(1); u32(0); cstr("sk.c"); cstr("/p")
            cstr("sk.dwo")
            u64(0x1122334455667788)
            if (version < 5) u32(0) // GNU_addr_base
            uleb(2); cstr("skel_fn"); u64(0x3000); u32(0x10)
            uleb(0); uleb(0)
        }.build()
        return wrapUnit(version, body, skeleton = true)
    }

    private fun unknownFormInfo(): ByteArray {
        // root abbrev1 expects stmt_list/name/comp_dir; child abbrev5 carries bad form.
        val body = ByteArrayBuilder().apply {
            uleb(1); u32(0); cstr("bad.c"); cstr("/p")
            uleb(5)              // subprogram with name form 0x6e
            u8(0x41)             // one byte of bogus payload
            uleb(0); uleb(0)
        }.build()
        return wrapUnit(4, body)
    }

    private fun outOfBoundsInfo(): ByteArray {
        // Manually craft: DWARF4 unit with abbrev offset pointing past the section.
        val b = ByteArrayBuilder()
        val bodyLen = 2 + 4 + 1 + 0
        b.u32(bodyLen.toLong())
        b.u16(4)
        b.u32(0x7fffffff) // bogus abbrev offset
        b.u8(8)
        return b.build()
    }

    private fun wrapUnit(version: Int, body: ByteArray, skeleton: Boolean = false): ByteArray {
        val b = ByteArrayBuilder()
        if (version >= 5) {
            val headerLen = 2 + 1 + 1 + 4 + 8
            val total = headerLen + body.size
            b.u32(total.toLong())
            b.u16(5)
            b.u8(if (skeleton) DW_UT_SKELETON else 0x01)
            b.u8(8)
            b.u32(0) // abbrev offset 0
            b.u64(0x1122334455667788)
        } else {
            val headerLen = 2 + 4 + 1
            b.u32((headerLen + body.size).toLong())
            b.u16(4)
            b.u32(0)
            b.u8(8)
        }
        b.bytes(body)
        return b.build()
    }

    // ---- line programs ----

    private fun lineProgram(version: Int): ByteArray {
        val lineBase = -5
        val lineRange = 14
        val opcodeBase = 13
        val stdLengths = intArrayOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1)

        val tables = ByteArrayBuilder()
        if (version <= 4) {
            // include_directories: a single empty entry terminates the list
            tables.u8(0)
            // file_names: main.c, dir=0, mtime=0, len=0, then NUL terminator
            tables.cstr("main.c"); tables.uleb(0); tables.uleb(0); tables.uleb(0)
            tables.u8(0)
        } else {
            // directories: one format (path, string), one entry
            tables.u8(1); tables.uleb(0x1); tables.uleb(DW_FORM_string.toLong())
            tables.uleb(1); tables.cstr("/proj/src")
            // files: one format (path, string), one entry
            tables.u8(1); tables.uleb(0x1); tables.uleb(DW_FORM_string.toLong())
            tables.uleb(1); tables.cstr("main.c")
        }

        val params = ByteArrayBuilder()
        params.u8(1) // min insn length
        if (version >= 5) params.u8(1) // maximum_operations_per_instruction (v5 only)
        params.u8(1) // default_is_stmt
        params.u8(lineBase and 0xff); params.u8(lineRange); params.u8(opcodeBase)
        stdLengths.forEach { params.u8(it) }

        val header = ByteArrayBuilder().apply { bytes(params.build()); bytes(tables.build()) }

        val prog = ByteArrayBuilder()
        fun setAddress(a: Long) {
            prog.u8(0)
            if (version >= 5) {
                prog.uleb(10); prog.u8(0x02); prog.u8(8); prog.u64(a)
            } else {
                prog.uleb(9); prog.u8(0x02); prog.u64(a)
            }
        }
        fun endSequence(a: Long) { setAddress(a); prog.u8(0); prog.uleb(1); prog.u8(0x01) }
        fun special(targetLine: Int) {
            val adj = targetLine - 1 - lineBase
            prog.u8((opcodeBase + adj * lineRange) and 0xff)
        }
        // sequence 1: 0x1000 main.c:10 -> :11@0x1020 -> :12@0x1030 -> end@0x1040
        setAddress(0x1000)
        special(10)
        prog.u8(DW_LNS_ADV_PC); prog.uleb(0x20)
        prog.u8(DW_LNS_ADV_LINE); prog.sleb(1)
        prog.u8(DW_LNS_COPY)
        prog.u8(DW_LNS_ADV_PC); prog.uleb(0x10)
        prog.u8(DW_LNS_ADV_LINE); prog.sleb(1)
        prog.u8(DW_LNS_COPY)
        endSequence(0x1040)
        // sequence 2: 0x2000 main.c:20 -> end@0x2010
        setAddress(0x2000)
        special(20)
        endSequence(0x2010)

        val out = ByteArrayBuilder()
        if (version >= 5) {
            // unit_length covers: version(2) + addr_size(1)+seg(1) + header_length(8) + header + program
            val total = 2 + 2 + 8 + header.size() + prog.size()
            out.u32(total.toLong()); out.u16(5)
            out.u8(8); out.u8(0)
        } else {
            // covers: version(2) + header_length(4) + header + program
            val total = 2 + 4 + header.size() + prog.size()
            out.u32(total.toLong()); out.u16(4)
        }
        out.u32(header.size().toLong())
        out.bytes(header.build())
        out.bytes(prog.build())
        return out.build()
    }

    // Standard opcode numbers used above
    const val DW_LNS_COPY = 0x01
    const val DW_LNS_ADV_PC = 0x02
    const val DW_LNS_ADV_LINE = 0x03
    const val DW_LNS_SET_FILE = 0x04
    const val DW_UT_SKELETON = 0x04
}
