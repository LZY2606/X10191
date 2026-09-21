package compass

import compass.dwarf.DebugBundleParser
import compass.dwarf.DebugInputs
import compass.elf.ElfParser
import compass.fixture.Fixtures5
import compass.resolve.AddressResolver
import compass.resolve.LoadEntry
import compass.resolve.LoadedModule
import compass.resolve.Snapshot
import compass.util.U64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Dwarf5SplitTest {

    private fun bundle(linkDwo: Boolean = true): compass.dwarf.DebugBundle {
        val pair = Fixtures5.splitDwarf5()
        val exe = ElfParser.parse(pair.exe)
        val dwo = if (linkDwo) listOf(ElfParser.parse(pair.dwo)) else emptyList()
        return DebugBundleParser.parse(DebugInputs(exe, dwo))
    }

    @Test
    fun linksSkeletonAndSplitByDwoId() {
        val b = bundle(true)
        val skel = b.cus.first { it.kind == "skeleton" }
        val split = b.cus.first { it.kind == "split" }
        assertEquals(U64(0x1234), skel.dwoId)
        assertEquals(1, b.splitLinks.size)
        assertEquals(split.offset, b.splitLinks[skel.offset])
    }

    @Test
    fun resolvesRnglistsAddrxAndSplitLineTable() {
        val b = bundle(true)
        val mod = LoadedModule(1, "a.out", b)
        val snap = Snapshot(1, "s", listOf(LoadEntry(mod, U64.ZERO, U64(0x5000), 1)))
        val r = AddressResolver().resolveParsed(snap, U64(0x5060), 0)
        assertEquals("splitfn", r.functionName)
        assertNotNull(r.line)
        assertEquals(28, r.line!!.line)
        assertEquals(5, r.line!!.dwarfVersion)
        assertEquals("split", r.line!!.lineSource)
        assertEquals("high", r.trust)
    }

    @Test
    fun missingDwoKeepsRangesButReportsPartialTrust() {
        val b = bundle(false)
        assertTrue(b.issues.any { it.code == "MISSING_DWO" })
        val mod = LoadedModule(1, "a.out", b)
        val snap = Snapshot(1, "s", listOf(LoadEntry(mod, U64.ZERO, U64(0x5000), 1)))
        val r = AddressResolver().resolveParsed(snap, U64(0x5020), 0)
        // skeleton ranges remain usable; the unnamed subprogram resolves but line info absent
        assertEquals("partial", r.trust)
        assertTrue(r.issues.any { "MISSING_DWO" in it })
    }
}
