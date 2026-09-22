package compass

import compass.dwarf.*
import compass.elf.ElfFile
import kotlin.test.*

class CompassTest {

    private fun registryOf(vararg blobs: ByteArray): Registry {
        val r = Registry()
        for (b in blobs) r.importElf(ElfFile.parse(b))
        return r
    }
    private fun query(r: Registry, addr: Long) =
        QueryEngine(r).query(QueryEngine(r).parseInput("0x${addr.toString(16)}"))

    // ---- special opcodes + end_sequence + multiple sequences ----
    @Test
    fun `line program parses special opcodes and multiple sequences`() {
        val r = registryOf(Fixtures.dwarf5Overlapping())
        val f = r.all().single()
        val unit = f.units.single()
        val lp = f.lineProgramFor(unit)!!
        assertEquals(5, lp.version)
        assertEquals(2, lp.sequences.size, "two end_sequence markers")
        val seq0 = lp.sequences[0]
        assertEquals(0x401000L, seq0.startAddress)
        assertTrue(seq0.endAddress > seq0.startAddress)
        // special opcode advanced line to 1 (line_base -5 => special(1) -> line 2)
        assertTrue(lp.rows.any { it.line >= 1 && !it.endSequence })
        assertTrue(lp.transitions.any { it.endSequence && it.opcode == "end_sequence" })
        val hit = lp.rowFor(0x401002)!!
        assertEquals("main.c", lp.fileOf(hit.fileIndex)!!.name)
    }

    // ---- overlapping functions: keep all candidates, narrow wins ----
    @Test
    fun `overlapping ranges keep all candidates and narrowest ranks first`() {
        val r = registryOf(Fixtures.dwarf5Overlapping())
        val q = query(r, 0x401024)
        val names = q.candidates.map { it.function }
        assertTrue("narrow_func" in names, "narrow function is a candidate")
        assertTrue("wide_func" in names, "wide function remains a legal candidate")
        assertEquals("narrow_func", q.candidates.first().function,
            "narrowest range ranks before wider overlap")
        assertEquals(2, q.candidates.count { it.explicitScore >= 2 })
    }

    // ---- high_pc two meanings ----
    @Test
    fun `high_pc absolute and constant-length forms both resolve`() {
        val r = registryOf(Fixtures.dwarf5Overlapping())
        val f = r.all().single()
        val byName = f.scopes.associateBy { it.name() }
        assertEquals(listOf(AddressRange(0x401000, 0x401060)), byName.getValue("wide_func").ranges)
        assertEquals(listOf(AddressRange(0x401020, 0x401030)), byName.getValue("narrow_func").ranges)
    }

    // ---- DWARF4 .debug_ranges incl. zero-length ----
    @Test
    fun `dwarf4 range lists including zero length match exactly`() {
        val r = registryOf(Fixtures.dwarf4Ranges())
        val f = r.all().single()
        val sc = f.scopes.single { it.name() == "fragmented" }
        assertTrue(sc.ranges.any { it.zeroLength && it.start == 0x403000L })
        val qZero = query(r, 0x403000)
        assertEquals("fragmented", qZero.candidates.firstOrNull()?.function)
        val qAdj = query(r, 0x403001)
        assertTrue(qAdj.candidates.none { it.function == "fragmented" },
            "zero-length range must not match address after start")
        val qFrag = query(r, 0x401004)
        assertEquals("fragmented", qFrag.candidates.first().function)
    }

    // ---- inline call chain ----
    @Test
    fun `inline chain orders frames leaf to outer with call site`() {
        val r = registryOf(Fixtures.dwarf5InlineChain())
        val q = query(r, 0x40100c)
        val top = q.candidates.first()
        assertEquals("leaf_helper", top.function)
        assertEquals(1, top.inlineDepth)
        val functions = top.inlineChain.map { it.function }
        assertEquals(listOf("outer", "leaf_helper"), functions)
        val leaf = top.inlineChain.last()
        assertEquals(42L, leaf.line)
        assertEquals(8L, leaf.column)
        assertTrue(top.tableVersion == 5)
    }

    // ---- unknown form isolates CU, cursor does not resync to garbage ----
    @Test
    fun `unknown form truncates CU without bogus DIEs`() {
        val r = registryOf(Fixtures.unknownForm())
        val f = r.all().single()
        val unit = f.units.single()
        assertTrue(unit.issues.any { it.severity == "error" && it.message.contains("unknown form") },
            "unknown form recorded as error: ${unit.issues}")
        // root DIE never got attributes; garbage bytes must not have become children
        assertTrue(unit.root.children.isEmpty())
        // Querying still works (line programs would if present) and never throws.
        val q = query(r, 0x409999)
        assertTrue(q.candidates.isEmpty())
    }

    // ---- out-of-bounds reference stays unresolved, hop capped, no crash ----
    @Test
    fun `out of bounds reference is reported unresolved`() {
        val r = registryOf(Fixtures.outOfBoundsRef())
        val f = r.all().single()
        val sub = f.scopes.first { it.die.tag == DW.TAG_subprogram }
        val names = DwarfNames { _, _ -> null }
        val resolved = names.name(sub.die, sub.unit)
        assertEquals("<unresolved-origin>", resolved)
    }

    // ---- address relocation via snapshot / load bias ----
    @Test
    fun `snapshot load bias relocates runtime address to file vaddr`() {
        val r = registryOf(Fixtures.relocatableDwarf5())
        val f = r.all().single()
        // file base 0x400000, runtime loaded at 0x7f0000000000 -> bias = runtime-0x400000
        val snapBase = 0x7f0000000000L
        val snap = SnapshotView(1, "crash", "now",
            listOf(SnapshotModule("a.out", f.id, snapBase)))
        val engine = QueryEngine(r)
        val input = engine.parseInput("0x${(snapBase + 0x1024).toString(16)}")
        val q = engine.query(input, snap)
        assertEquals(snapBase - 0x400000L, q.loadBias)
        assertEquals("narrow_func", q.candidates.first().function)
        // relative form
        val rel = engine.query(engine.parseInput("+0x401024"), snap)
        assertEquals("narrow_func", rel.candidates.first().function)
    }

    // ---- split DWARF5: linked case ----
    @Test
    fun `split dwarf links dwo and resolves deferred addrx`() {
        val pair = Fixtures.splitDwarf5()
        val r = Registry()
        r.importElf(ElfFile.parse(pair.skeleton))
        r.importElf(ElfFile.parse(pair.dwo))
        val f = r.all().single { it.units.any { u -> u.isSplit } }
        val splitUnit = f.units.single { it.isSplit }
        val scope = f.scopes.single { it.name() == "inlined_in_dwo" }
        val low = (scope.die.attr(DW.AT_low_pc)?.value as? FormValue.Address)?.value
        assertEquals(0x401000L, low, "deferred addrx resolves from skeleton .debug_addr")
        val q = query(r, 0x401004)
        assertTrue(q.candidates.any { it.function == "inlined_in_dwo" || it.function == "skeleton_concrete" })
    }

    // ---- split DWARF5: missing dwo ----
    @Test
    fun `missing dwo keeps skeleton conclusions and flags uncertainty`() {
        val pair = Fixtures.splitDwarf5()
        val r = registryOf(pair.skeleton)
        val skel = r.all().single()
        val unit = skel.units.single { it.isSkeleton }
        assertNull(unit.linkedDwoFileId)
        assertTrue(unit.issues.any { "no matching .dwo" in it.message })
        val q = query(r, 0x401004)
        val c = q.candidates.firstOrNull { it.cuOffset == unit.unitOffset }
        assertNotNull(c)
        assertTrue(c!!.notes.any { it.contains(".dwo") })
    }

    // ---- ordering independent of import order ----
    @Test
    fun `query ranking is independent of import order`() {
        val a = Fixtures.dwarf5Overlapping()
        val b = Fixtures.dwarf4Ranges()
        val r1 = registryOf(a, b)
        val r2 = registryOf(b, a)
        val q1 = QueryEngine(r1).query(QueryEngine(r1).parseInput("0x401024"))
        val q2 = QueryEngine(r2).query(QueryEngine(r2).parseInput("0x401024"))
        val key1 = q1.candidates.map { "${it.fileSha256}:${it.cuOffset}:${it.matchedRange.start}:${it.function}" }
        val key2 = q2.candidates.map { "${it.fileSha256}:${it.cuOffset}:${it.matchedRange.start}:${it.function}" }
        assertEquals(key1, key2)
    }

    // ---- digest persistence per section ----
    @Test
    fun `elf parser keeps section bytes digests`() {
        val r = registryOf(Fixtures.dwarf5Overlapping())
        val f = r.all().single()
        val info = f.elf.dwarfSection(".debug_info")!!
        assertNotNull(info.sha256)
        assertEquals(64, info.sha256!!.length)
        assertEquals(info.sha256, compass.elf.ElfFile.sha256Hex(info.data))
    }
}
