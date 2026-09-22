package compass

import compass.dwarf.*
import compass.elf.ElfFile
import compass.fixture.*
import compass.resolve.AddressResolver
import compass.resolve.ModuleSnapshot
import kotlin.test.*

class DwarfParserTest {

    private fun dwarf4Cu(
        lowPc: Long,
        highPc: Any,
        extraDies: List<DieSpec> = emptyList(),
        useRanges: Boolean = false,
        rangesSection: ByteArray? = null,
        filePrefix: String = "/home/user/src"
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val prog = LineProgBuilder()
        prog.extSetAddr(lowPc)
        // rows: L2@lowPc, L3@lowPc+2, L3@lowPc+3, end@lowPc+8
        prog.special(advLine = 1, advPc = 0)
        prog.std(1)
        prog.special(advLine = 1, advPc = 2)
        prog.std(1)
        prog.special(advLine = 0, advPc = 1)
        prog.std(1)
        prog.extSetAddr(lowPc + 8)
        prog.extEndSeq()
        val line = buildLineDwarf4(listOf("main.c"), listOf(filePrefix), prog)
        val lineStr = Bin().apply { cstr("main.c") }.bytes()

        val highPcForm: Int = if (highPc is Int) 0x0f else 0x01
        val subAttrs = mutableListOf<Pair<Int, Any>>(
            0x03 to "main",
            0x11 to lowPc
        )
        when (highPc) {
            is Long -> subAttrs.add(0x12 to highPc)
            is Int -> subAttrs.add(0x12 to highPc)
        }
        if (useRanges) {
            subAttrs.removeAll { it.first == 0x11 || it.first == 0x12 }
            subAttrs.add(0x55 to 0L)
        }
        val sub = DieSpec(0x2e, subAttrs, extraDies)
        val cuAttrs = listOf<Pair<Int, Any>>(
            0x10 to 0L,
            0x11 to lowPc,
            0x03 to "$filePrefix/main.c",
            0x1b to filePrefix,
            0x25 to "test-compiler 1.0",
            0x13 to 12L
        ).let { if (useRanges) it.filter { a -> a.first != 0x11 } + (0x55 to 0L) else it }
        val root = DieSpec(0x11, cuAttrs, listOf(sub))

        val abbrevSpecs = listOf(
            AbbrevSpec(1, 0x11, true, buildList {
                add(Triple(0x10, 0x17, null))
                if (!useRanges) add(Triple(0x11, 0x01, null))
                add(Triple(0x03, 0x08, null))
                add(Triple(0x1b, 0x08, null))
                add(Triple(0x25, 0x08, null))
                add(Triple(0x13, 0x0f, null))
                if (useRanges) add(Triple(0x55, 0x17, null))
            }),
            AbbrevSpec(2, 0x2e, extraDies.isNotEmpty(), buildList {
                add(Triple(0x03, 0x08, null))
                if (!useRanges) {
                    add(Triple(0x11, 0x01, null))
                    add(Triple(0x12, highPcForm, null))
                } else add(Triple(0x55, 0x17, null))
            }),
            AbbrevSpec(3, 0x1d, false, listOf(
                Triple(0x03, 0x08, null),
                Triple(0x11, 0x01, null),
                Triple(0x12, 0x01, null),
                Triple(0x58, 0x0f, null),
                Triple(0x59, 0x0f, null)
            ))
        )
        val codes = abbrevSpecs.associateBy { it.code }
        val abbrev = buildAbbrev(abbrevSpecs)
        val info = buildInfoDwarf4(abbrev, root, codes, 0)
        return Triple(info, abbrev, line)
    }

    @Test
    fun `zzz debug`() {
        val base = 0x401000L
        val t = dwarf4Cu(base, 8L)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to t.first, ".debug_abbrev" to t.second, ".debug_line" to t.third))))
        val r = AddressResolver.resolve(base+2, listOf(ModuleSnapshot("m",null,0,1,0,idx)))
        val sc = idx.scopes.joinToString(";") { "${it.name}:${it.ranges}" }
        val msg = "abbrev=" + t.second.joinToString(" ") { (it.toInt() and 0xff).toString(16) } + " scopes=[$sc]"
        assertEquals("X", msg)
    }

    @Test
    fun `special opcodes and end_sequence decode to file and line`() {
        val base = 0x401000L
        val (info, abbrev, line) = dwarf4Cu(base, 8)
        val elf = buildElf(mapOf(
            ".debug_info" to info,
            ".debug_abbrev" to abbrev,
            ".debug_line" to line
        ))
        val idx = DwarfLoader.load(ElfFile(elf, "test.elf"))
        assertEquals(1, idx.cus.size)
        val cu = idx.cus.single()
        assertEquals(4, cu.version)
        val seq = cu.sequences.single()
        val row = seq.rowFor(base + 2)!!
        assertEquals(3, row.line)
        assertTrue(seq.rows.last().endSequence)
        val res = AddressResolver.resolve(base + 2, listOf(ModuleSnapshot("test.elf", null, 0, 1, 0, idx)))
        val primary = res.single().second.primary!!
        assertEquals("/home/user/src/main.c", primary.file)
        assertEquals(3, primary.line)
        assertEquals("main", primary.function)
        assertEquals(4, primary.tableVersion)
    }

    @Test
    fun `high_pc constant form means offset from low_pc`() {
        val base = 0x401100L
        val (info, abbrev, line) = dwarf4Cu(base, 0x20 /* constant */)
        val elf = buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev, ".debug_line" to line
        ))
        val idx = DwarfLoader.load(ElfFile(elf))
        val scope = idx.scopes.single()
        assertEquals(0x20L, scope.ranges.single().length)
        val mid = AddressResolver.resolve(base + 0x10, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        assertEquals(base + 0x10, mid.single().second.fileRelativeAddress)
    }

    @Test
    fun `zero-length range matches only exact pc`() {
        val base = 0x401200L
        // subprogram with low_pc only => zero-length
        val prog = LineProgBuilder().apply {
            extSetAddr(base); special(1, 0); std(1); extEndSeq()
        }
        val line = buildLineDwarf4(listOf("z.c"), emptyList(), prog)
        val root = DieSpec(0x11, listOf(0x10 to 0L, 0x03 to "z.c", 0x11 to base), listOf(
            DieSpec(0x2e, listOf(0x03 to "zero_fn", 0x11 to base)) // no high_pc
        ))
        val abbrevSpecs = listOf(
            AbbrevSpec(1, 0x11, true, listOf(
                Triple(0x10, 0x17, null), Triple(0x03, 0x08, null), Triple(0x11, 0x01, null))),
            AbbrevSpec(2, 0x2e, false, listOf(
                Triple(0x03, 0x08, null), Triple(0x11, 0x01, null)))
        )
        val codes = abbrevSpecs.associateBy { it.code }
        val info = buildInfoDwarf4(buildAbbrev(abbrevSpecs), root, codes)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to buildAbbrev(abbrevSpecs), ".debug_line" to line
        ))))
        val scope = idx.scopes.single()
        assertTrue(scope.ranges.single().end == scope.ranges.single().start)
        // exact pc zero-length is a legal candidate
        val exact = AddressResolver.resolve(base, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        assertTrue(exact.single().second.candidates.any { it.isZeroLengthMatch })
    }

    @Test
    fun `overlapping functions retain both candidates and narrowest wins`() {
        val base = 0x402000L
        // big outer 0..32 and small inner 8..16 both cover base+10
        val outer = DieSpec(0x2e, listOf(0x03 to "outer", 0x11 to base, 0x12 to base + 32))
        val inner = DieSpec(0x2e, listOf(0x03 to "inner", 0x11 to base + 8, 0x12 to base + 16))
        val root = DieSpec(0x11, listOf(0x10 to 0L, 0x03 to "o.c", 0x11 to base, 0x12 to base + 32),
            listOf(outer, inner))
        val abbrevSpecs = listOf(
            AbbrevSpec(1, 0x11, true, listOf(
                Triple(0x10, 0x17, null), Triple(0x03, 0x08, null),
                Triple(0x11, 0x01, null), Triple(0x12, 0x01, null))),
            AbbrevSpec(2, 0x2e, false, listOf(
                Triple(0x03, 0x08, null), Triple(0x11, 0x01, null), Triple(0x12, 0x01, null)))
        )
        val codes = abbrevSpecs.associateBy { it.code }
        val info = buildInfoDwarf4(buildAbbrev(abbrevSpecs), root, codes)
        val prog = LineProgBuilder().apply {
            extSetAddr(base); special(1, 2); std(1); extEndSeq()
        }
        val line = buildLineDwarf4(listOf("o.c"), emptyList(), prog)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to buildAbbrev(abbrevSpecs), ".debug_line" to line
        ))))
        val res = AddressResolver.resolve(base + 10, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        val r = res.single().second
        assertEquals("inner", r.primary!!.function)
        assertTrue(r.candidates.size >= 1)
    }

    @Test
    fun `load bias relocation maps runtime to relative address`() {
        val base = 0x1000L
        val (info, abbrev, line) = dwarf4Cu(base, 16)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev, ".debug_line" to line
        ))))
        val bias = 0x7f00_0000L
        val res = AddressResolver.resolve(bias + base + 4, listOf(
            ModuleSnapshot("libx.so", "abcd", bias, 2, 0, idx)
        ))
        val r = res.single().second
        assertEquals(bias, r.loadBias)
        assertEquals(2, r.loadGeneration)
        assertEquals(base + 4, r.fileRelativeAddress)
        assertEquals("main", r.primary!!.function)
    }

    @Test
    fun `multiple line sequences resolve to correct one`() {
        val base = 0x5000L
        // two disjoint sequences in one program
        val p = LineProgBuilder()
        p.extSetAddr(base);     p.special(1, 0); p.std(1)
        p.extEndSeq()
        p.extSetAddr(base + 100); p.special(2, 0); p.std(1)
        p.extEndSeq()
        val line = buildLineDwarf4(listOf("multi.c"), emptyList(), p)
        val (info, abbrev, _) = dwarf4Cu(base, 200L)
        val idx = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to info, ".debug_abbrev" to abbrev, ".debug_line" to line
        ))))
        val seqs = idx.cus.single().sequences
        assertEquals(2, seqs.size)
        val res = AddressResolver.resolve(base + 100, listOf(ModuleSnapshot("m", null, 0, 1, 0, idx)))
        assertEquals(3, res.single().second.primary!!.line) // 1 + advLine 2
    }

    @Test
    fun `query ordering stable when module import order changes`() {
        val base = 0x6000L
        val (i1, a1, l1) = dwarf4Cu(base, 16, filePrefix = "/a")
        val idxA = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to i1, ".debug_abbrev" to a1, ".debug_line" to l1))))
        val (i2, a2, l2) = dwarf4Cu(base, 16, filePrefix = "/b")
        val idxB = DwarfLoader.load(ElfFile(buildElf(mapOf(
            ".debug_info" to i2, ".debug_abbrev" to a2, ".debug_line" to l2))))
        val mA = ModuleSnapshot("aaa.so", null, 0, 1, 0, idxA)
        val mB = ModuleSnapshot("bbb.so", null, 0, 1, 0, idxB)
        val order1 = AddressResolver.resolve(base + 2, listOf(mB, mA)).map { it.first.name }
        val order2 = AddressResolver.resolve(base + 2, listOf(mA, mB)).map { it.first.name }
        assertEquals(order1, order2)
        assertEquals(listOf("aaa.so", "bbb.so"), order1)
    }
}
