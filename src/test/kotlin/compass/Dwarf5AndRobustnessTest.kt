package compass

import compass.dwarf.*
import compass.elf.DwarfParseException
import compass.elf.ElfFile
import compass.fixture.*
import compass.resolve.AddressResolver
import compass.resolve.ModuleSnapshot
import kotlin.test.*

class Dwarf5AndRobustnessTest {

    private fun makeInfo5(
        rootAttrs: List<Pair<Int, Any>>,
        dies: List<DieSpec>,
        abbrevSpecs: List<AbbrevSpec>,
        unitType: Int = 0x01,
        dwoId: Long? = null,
        addrBase: Long? = null
    ): Pair<ByteArray, ByteArray> {
        val codes = abbrevSpecs.associateBy { it.code }
        val b = Bin()
        val root = DieSpec(0x11, rootAttrs, dies)
        encodeDies(b, listOf(root), codes)
        val dieBytes = b.bytes()
        val header = Bin()
        header.u16(5)
        header.u8(unitType)
        header.u8(8)
        header.u32(0)
        if (dwoId != null) header.u64(dwoId)
        header.bytes(dieBytes)
        val hb = header.bytes()
        val out = Bin()
        out.u32(hb.size.toLong())
        out.bytes(hb)
        return out.bytes() to buildAbbrev(abbrevSpecs)
    }

    @Test
    fun `DWARF5 line program with line_strp resolves`() {
        val base = 0x3000L
        val lineStr = Bin().apply { cstr("d5.c") }.bytes()
        val prog = LineProgBuilder().apply {
            extSetAddr(base); special(1, 0); std(1); special(1, 3); std(1); extEndSeq()
        }
        val line = buildLineDwarf5("d5.c", prog, lineStr, 0)
        val (info, abbrev) = makeInfo5(
            listOf(0x10 to 0L, 0x03 to "d5.c", 0x11 to base, 0x12 to 16L),
            listOf(DieSpec(0x2e, listOf(0x03 to "d5fn", 0x11 to base, 0x12 to 16L))),
            listOf(
                AbbrevSpec(1, 0x11, true, listOf(
                    Triple(0x10, 0x17, null), Triple(0x03, 0x08, null),
                    Triple(0x11, 0x01, null), Triple(0x12, 0x01, null))),
                AbbrevSpec(2, 0x2e, false, listOf(
                    Triple(0x03, 0x08, null), Triple(0x11, 0x01, null), Triple(0x12, 0x01, null)))
            )
        )
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev,
            ".debug_line" to line, ".debug_line_str" to lineStr
        ))))
        val cu = idx.cus.single()
        assertEquals(5, cu.version)
        val res = AddressResolver.resolve(base + 3, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        val primary = res.single().second.primary!!
        assertEquals("d5.c", primary.file)
        assertEquals(5, primary.tableVersion)
    }

    @Test
    fun `skeleton CU with missing dwo still gives line rows with a warning`() {
        val base = 0x7000L
        val prog = LineProgBuilder().apply {
            extSetAddr(base); special(1, 0); std(1); extEndSeq()
        }
        val line = buildLineDwarf5("sk.c", prog, Bin().apply { cstr("sk.c") }.bytes(), 0)
        val (info, abbrev) = makeInfo5(
            listOf(0x10 to 0L, 0x03 to "sk.c", 0x76 to "sk.dwo", 0x11 to base, 0x12 to 8L),
            listOf(DieSpec(0x2e, listOf(0x03 to "skfn", 0x11 to base, 0x12 to 8L))),
            listOf(
                AbbrevSpec(1, 0x41, true, listOf(
                    Triple(0x10, 0x17, null), Triple(0x03, 0x08, null), Triple(0x76, 0x08, null),
                    Triple(0x11, 0x01, null), Triple(0x12, 0x01, null))),
                AbbrevSpec(2, 0x2e, false, listOf(
                    Triple(0x03, 0x08, null), Triple(0x11, 0x01, null), Triple(0x12, 0x01, null)))
            ),
            unitType = 0x04, dwoId = 0xdeadbeefL
        )
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev,
            ".debug_line" to line, ".debug_line_str" to Bin().apply { cstr("sk.c") }.bytes()
        ))))
        val cu = idx.cus.single()
        assertTrue(cu.skeletonFor)
        assertTrue(cu.notes.any { it.contains("sk.dwo") && it.contains("split") })
        val res = AddressResolver.resolve(base, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        assertNotNull(res.single().second.primary)
        assertEquals("sk.c", res.single().second.primary!!.file)
    }

    @Test
    fun `unknown variable-length form aborts CU instead of producing garbage`() {
        // CU with an abbrev carrying an unknown form 0x99 after a valid name; parser must note abort,
        // not misalign and fabricate DIEs.
        val abbrevSpecs = listOf(
            AbbrevSpec(1, 0x11, true, listOf(
                Triple(0x03, 0x08, null),
                Triple(0x1234, 0x99, null))) // unknown
        )
        val b = Bin()
        b.uleb(1); b.cstr("x.c")
        // no trailing bytes — unknown form immediately aborts
        val abbrev = buildAbbrev(abbrevSpecs)
        val dieData = b.bytes()
        val header = Bin().apply {
            u16(4); u32(0); u8(8); bytes(dieData)
        }.bytes()
        val info = Bin().apply { u32(header.size.toLong()); bytes(header) }.bytes()
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev
        ))))
        // CU present but DIE tree aborted; no fabricated children
        val cu = idx.cus.single()
        assertTrue(cu.notes.any { it.contains("DIE tree parse aborted") || it.contains("unknown") })
        assertEquals(0, idx.scopes.size)
    }

    @Test
    fun `out-of-bounds reference does not escape bounds`() {
        // strp pointing far past .debug_str
        val abbrevSpecs = listOf(
            AbbrevSpec(1, 0x11, false, listOf(Triple(0x03, 0x0e, null)))
        )
        val b = Bin(); b.uleb(1); b.u32(0xfffffff0L)
        val abbrev = buildAbbrev(abbrevSpecs)
        val header = Bin().apply { u16(4); u32(0); u8(8); bytes(b.bytes()) }.bytes()
        val info = Bin().apply { u32(header.size.toLong()); bytes(header) }.bytes()
        assertFailsWith<DwarfParseException> {
            DwarfLoader.load(ElfFile(buildElf(mapOf(
                ".debug_info" to info, ".debug_abbrev" to abbrev, ".debug_str" to ByteArray(4)
            ))))
        }.let { assertTrue(it.message!!.contains("out of bounds")) }
    }

    @Test
    fun `corrupt section length is isolated to a parse failure`() {
        val raw = ByteArray(256)
        raw[0] = 0x7f; raw[1] = 'E'.code.toByte(); raw[2] = 'L'.code.toByte(); raw[3] = 'F'.code.toByte()
        raw[4] = 2; raw[5] = 1; raw[6] = 1
        // huge shoff
        for (i in 0 until 8) raw[40 + i] = 0xff.toByte()
        assertFailsWith<DwarfParseException> { ElfFile(raw, "bad") }
    }

    @Test
    fun `dwarf5 rnglists START_LENGTH is parsed`() {
        val base = 0x8000L
        // .debug_rnglists: just a list body: base_address(0x06, addr), start_length(0x07,a,l), end(0)
        val rl = Bin().apply {
            u8(0x06); u64(base)
            u8(0x07); u64(base); u64(24)
            u8(0x00)
        }.bytes()
        val (info, abbrev) = makeInfo5(
            listOf(0x10 to 0L, 0x03 to "r.c", 0x55 to 0L),
            listOf(DieSpec(0x2e, listOf(0x03 to "rfn", 0x55 to 0L))),
            listOf(
                AbbrevSpec(1, 0x11, true, listOf(
                    Triple(0x10, 0x17, null), Triple(0x03, 0x08, null), Triple(0x55, 0x17, null))),
                AbbrevSpec(2, 0x2e, false, listOf(
                    Triple(0x03, 0x08, null), Triple(0x55, 0x17, null)))
            )
        )
        val prog = LineProgBuilder().apply {
            extSetAddr(base); special(1, 0); std(1); extEndSeq()
        }
        val line = buildLineDwarf5("r.c", prog, Bin().apply { cstr("r.c") }.bytes(), 0)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev,
            ".debug_line" to line, ".debug_line_str" to Bin().apply { cstr("r.c") }.bytes(),
            ".debug_rnglists" to rl
        ))))
        val cu = idx.cus.single()
        assertEquals(base, cu.ranges.single().start)
        assertEquals(24L, cu.ranges.single().length)
    }
}
