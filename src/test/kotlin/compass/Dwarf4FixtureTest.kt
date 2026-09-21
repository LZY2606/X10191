package compass

import compass.dwarf.DebugBundleParser
import compass.dwarf.DebugInputs
import compass.dwarf.DwTag
import compass.elf.ElfParser
import compass.fixture.Fixtures
import compass.resolve.AddressResolver
import compass.resolve.LoadEntry
import compass.resolve.LoadedModule
import compass.resolve.Snapshot
import compass.util.U64
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Dwarf4FixtureTest {

    private fun load(): Pair<DebugInputs, compass.dwarf.DebugBundle> {
        val fx = Fixtures.dwarf4()
        val elf = ElfParser.parse(fx.elf)
        val inputs = DebugInputs(elf, emptyList())
        return inputs to DebugBundleParser.parse(inputs)
    }

    @Test
    fun parsesSectionsAndCu() {
        val (_, bundle) = load()
        assertEquals(1, bundle.cus.size)
        val cu = bundle.cus.single()
        assertEquals(4, cu.dwarfVersion)
        assertEquals("main.c", cu.name)
        assertTrue(cu.parsedCompletely)
        val subs = cu.dies.filter { it.tag == DwTag.SUBPROGRAM }
        assertEquals(5, subs.size)
    }

    @Test
    fun highPcBothMeanings() {
        val (_, bundle) = load()
        val cu = bundle.cus.single()
        val outer = cu.dies.first { it.name == "outer" }
        assertEquals(U64(0x1000), outer.ranges.single().start)
        assertEquals(U64(0x1080), outer.ranges.single().end) // constant offset meaning
        val compute = cu.dies.first { it.name == "compute" }
        assertEquals(U64(0x2000), compute.ranges.single().start)
        assertEquals(U64(0x2100), compute.ranges.single().end) // absolute address meaning
    }

    @Test
    fun lineProgramSpecialOpcodesAndSequences() {
        val (_, bundle) = load()
        val lp = bundle.linePrograms.single()
        assertEquals(2, lp.sequences.size, "two end_sequence sequences")
        assertEquals("main.c", lp.files[1].path)
        val rows = lp.rows.filter { !it.endSequence }
        assertTrue(rows.any { it.address == U64(0x1000) && it.line == 10 })
        assertTrue(rows.any { it.address == U64(0x2050) && it.line == 31 })
    }

    @Test
    fun resolvesAddressesWithNarrowestRangeAndInlineChain() {
        val fx = Fixtures.dwarf4()
        val elf = ElfParser.parse(fx.elf)
        val bundle = DebugBundleParser.parse(DebugInputs(elf, emptyList()))
        val mod = LoadedModule(1, "a.out", bundle)
        val snap = Snapshot(1, "s1", listOf(
            LoadEntry(mod, U64(0), U64(0x1000), 1)
        ))
        val resolver = AddressResolver()

        val inline = resolver.resolveParsed(snap, U64(0x2058), 0)
        assertEquals("helper", inline.functionName)
        assertEquals(1, inline.candidates.first { it.selected }.inlineChain.last().depth)
        assertEquals("compute", inline.candidates.first { it.selected }.inlineChain.first().name)
        assertNotNull(inline.line)
        assertEquals(31, inline.line!!.line)
        assertEquals(4, inline.cuDwarfVersion)

        val overlap = resolver.resolveParsed(snap, U64(0x3030), 0)
        // equal-width overlap -> explicit priority + stable tiebreak; both retained as candidates
        val names = overlap.candidates.map { it.name }.toSet()
        assertTrue("hot" in names && "cold" in names)
        assertEquals(2, overlap.candidates.size)

        val zeroLen = resolver.resolveParsed(snap, U64(0x4000), 0)
        assertEquals("point", zeroLen.functionName)
    }

    @Test
    fun loadBiasRelocation() {
        val fx = Fixtures.dwarf4()
        val elf = ElfParser.parse(fx.elf)
        val bundle = DebugBundleParser.parse(DebugInputs(elf, emptyList()))
        val mod = LoadedModule(1, "a.out", bundle)
        // binary linked at vaddr 0x1000, runtime PC 0x7f001040 -> bias = runtime-vaddr
        val bias = U64(0x7f001040L - 0x1040)
        val snap = Snapshot(1, "s1", listOf(LoadEntry(mod, bias, U64(0x1000), 2)))
        val result = AddressResolver().resolveParsed(snap, U64(0x7f001040), 0)
        assertEquals("outer", result.functionName)
        assertEquals(U64(0x1040), result.relativeAddress)
        assertEquals(bias, result.loadBias)
        assertEquals(2, result.snapshotGeneration)
    }
}
