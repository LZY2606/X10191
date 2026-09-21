@file:Suppress("ArrayInDataClass")
package compass

import compass.dwarf.DebugBundleParser
import compass.dwarf.DebugInputs
import compass.dwarf.DwTag
import compass.elf.ElfParser
import compass.fixture.BytesBuilder
import compass.fixture.DwarfFixture
import compass.fixture.ElfWriter
import compass.fixture.FixAttr
import compass.fixture.FixDie
import compass.fixture.FixForm
import compass.fixture.compileUnit
import compass.fixture.dwarf32Unit
import compass.fixture.dwarf4CuHeader
import compass.resolve.AddressResolver
import compass.resolve.LoadEntry
import compass.resolve.LoadedModule
import compass.resolve.Snapshot
import compass.util.U64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RobustnessTest {

    private fun elfWith(vararg sec: Pair<String, ByteArray>): ByteArray {
        val w = ElfWriter()
        for ((n, d) in sec) {
            if (n == ".text") w.addSection(n, type = 1, flags = 6, addr = 0x1000, data = d, addralign = 16)
            else w.addSection(n, data = d)
        }
        if (sec.none { it.first == ".text" }) {
            w.addSection(".text", type = 1, flags = 6, addr = 0x1000, data = ByteArray(0x1000), addralign = 16)
        }
        w.addLoadSegment(offset = 0x1000, vaddr = 0x1000, filesz = 0x1000)
        return w.build()
    }

    private fun v4Cu(root: FixDie): ByteArray = dwarf32Unit(dwarf4CuHeader() + compileUnit(root).infoBody)
    private fun abbrev(root: FixDie) = compileUnit(root).abbrev

    /** Unknown form aborts the CU but keeps previously-read DIEs; later CUs still parse. */
    @Test
    fun unknownFormIsolatesCuWithoutCursorDrift() {
        // CU1: good function goodfn
        val good = FixDie(DwarfFixture.TAG_COMPILE_UNIT, children = listOf(
            FixDie(DwarfFixture.TAG_SUBPROGRAM, attrs = listOf(
                FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("goodfn")),
                FixAttr(DwarfFixture.AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x1000)),
                FixAttr(DwarfFixture.AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x10))
            ))
        ), attrs = listOf(
            FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("good.c")),
            FixAttr(DwarfFixture.AT_STMT_LIST, DwarfFixture.FORM_SEC_OFFSET, FixForm.SecOff(0))
        ))
        // CU2: subprogram with unknown form 0x7e followed by junk bytes
        val bad = FixDie(DwarfFixture.TAG_COMPILE_UNIT, children = listOf(
            FixDie(DwarfFixture.TAG_SUBPROGRAM, attrs = listOf(
                FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("badfn")),
                FixAttr(0x6f00, 0x99, FixForm.Unknown(0x99, consume = 4)),
                FixAttr(DwarfFixture.AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x2000))
            ))
        ), attrs = listOf(
            FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("bad.c"))
        ))
        val info1 = v4Cu(good)
        val info2raw = dwarf4CuHeader() + compileUnit(bad).infoBody
        // info2raw layout: ... "badfn\0" + 4 unknown-form bytes + 8-byte trailing low_pc.
        // Drop the final low_pc (8 bytes); the parser must stop at the unknown form, aligned
        // inside the CU length so the next CU is unaffected.
        check(info2raw.size >= 8)
        val info2 = dwarf32Unit(info2raw.copyOfRange(0, info2raw.size - 8))

        val info = info1 + info2
        // abbrev tables: concatenate both at offsets 0 and good-abbrev length
        val ab1 = compileUnit(good).abbrev
        // build merged abbrev by concatenation; second CU header must point at ab1.size
        val ab2 = compileUnit(bad).abbrev
        val abbrev = ab1 + ab2
        // patch CU2 abbrev offset (bytes [4+2 .. 4+6) within its unit, i.e. after length+version)
        val mergedInfo = info1.copyOf() + run {
            val arr = info2.copyOf()
            // offset inside unit content starts right after 4-byte length + 2-byte version
            arr[6] = (ab1.size and 0xff).toByte()
            arr[7] = ((ab1.size ushr 8) and 0xff).toByte()
            arr[8] = ((ab1.size ushr 16) and 0xff).toByte()
            arr[9] = ((ab1.size ushr 24) and 0xff).toByte()
            arr
        }

        val elf = elfWith(".debug_info" to mergedInfo, ".debug_abbrev" to abbrev)
        val bundle = DebugBundleParser.parse(DebugInputs(ElfParser.parse(elf), emptyList()))
        assertEquals(2, bundle.cus.size, "both CUs scanned")
        val cu1 = bundle.cus[0]
        assertTrue(cu1.parsedCompletely)
        assertEquals("goodfn", cu1.dies.first { it.tag == DwTag.SUBPROGRAM }.name)
        val cu2 = bundle.cus[1]
        assertFalse(cu2.parsedCompletely)
        assertTrue(cu2.issues.any { it.code == "UNKNOWN_FORM" })
        // earlier DIEs in the bad CU retained
        assertTrue(cu2.dies.any { it.tag == DwTag.COMPILE_UNIT })
        // good CU still resolves
        val mod = LoadedModule(1, "a", bundle)
        val snap = Snapshot(1, "s", listOf(LoadEntry(mod, U64.ZERO, U64(0x1000), 1)))
        val r = AddressResolver().resolveParsed(snap, U64(0x1005), 0)
        assertEquals("goodfn", r.functionName)
    }

    /** abstract_origin pointing nowhere yields a REF_OUT_OF_BOUNDS warning but ranges stay usable. */
    @Test
    fun outOfBoundsReferenceDoesNotCrashResolution() {
        val inlined = FixDie(DwarfFixture.TAG_INLINED, attrs = listOf(
            FixAttr(DwarfFixture.AT_ABSTRACT_ORIGIN, DwarfFixture.FORM_REF4, FixForm.Data4(0xdeadbeef)),
            FixAttr(DwarfFixture.AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(0x1020)),
            FixAttr(DwarfFixture.AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x10)),
            FixAttr(DwarfFixture.AT_CALL_LINE, DwarfFixture.FORM_DATA2, FixForm.Data2(7))
        ))
        val root = FixDie(DwarfFixture.TAG_COMPILE_UNIT, children = listOf(inlined), attrs = listOf(
            FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("oob.c"))
        ))
        val compiled = compileUnit(root)
        val info = dwarf32Unit(dwarf4CuHeader() + compiled.infoBody)
        val elf = elfWith(".debug_info" to info, ".debug_abbrev" to compiled.abbrev)
        val bundle = DebugBundleParser.parse(DebugInputs(ElfParser.parse(elf), emptyList()))
        val issue = bundle.cus.single().issues.firstOrNull { it.code == "REF_OUT_OF_BOUNDS" }
        assertTrue(issue != null, "expected REF_OUT_OF_BOUNDS issue, got ${bundle.cus.single().issues}")
        val mod = LoadedModule(1, "a", bundle)
        val snap = Snapshot(1, "s", listOf(LoadEntry(mod, U64.ZERO, U64(0x1000), 1)))
        val r = AddressResolver().resolveParsed(snap, U64(0x1025), 0)
        // range itself still matches even though the name chain could not be resolved
        assertEquals(0x1025, r.relativeAddress?.v?.toInt() ?: -1)
        assertTrue(r.candidates.any { it.range?.start == U64(0x1020) })
    }

    /** A truncated .debug_info produces an issue instead of an exception. */
    @Test
    fun truncatedDebugInfoIsReportedGracefully() {
        val good = FixDie(DwarfFixture.TAG_COMPILE_UNIT, attrs = listOf(
            FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("x.c"))
        ))
        val compiled = compileUnit(good)
        // claim a unit length far beyond the section
        val bogus = BytesBuilder().u32(0x10000).u16(4).u32(0).u8(8).u8(1).build()
        val elf = elfWith(".debug_info" to bogus, ".debug_abbrev" to compiled.abbrev)
        val bundle = DebugBundleParser.parse(DebugInputs(ElfParser.parse(elf), emptyList()))
        assertTrue(bundle.cus.first().issues.any { it.code == "BAD_CU_HEADER" })
    }

    /** Same modules imported in opposite order resolve identically (stable tie-breaks). */
    @Test
    fun resultIndependentOfImportOrder() {
        val fx1 = orderFixture("alpha", 0x3000)
        val fx2 = orderFixture("beta", 0x3000)
        val b1 = DebugBundleParser.parse(DebugInputs(ElfParser.parse(fx1.elf), listOf(ElfParser.parse(fx2.elf))))
        val b2 = DebugBundleParser.parse(DebugInputs(ElfParser.parse(fx2.elf), listOf(ElfParser.parse(fx1.elf))))
        // companion merge only picks sections absent in main; emulate two independent modules instead:
        val bundleA = DebugBundleParser.parse(DebugInputs(ElfParser.parse(fx1.elf), emptyList()))
        val bundleB = DebugBundleParser.parse(DebugInputs(ElfParser.parse(fx2.elf), emptyList()))

        fun resolve(firstId: Long, first: compass.dwarf.DebugBundle, secondId: Long, second: compass.dwarf.DebugBundle) =
            AddressResolver().resolveParsed(
                Snapshot(1, "s", listOf(
                    LoadEntry(LoadedModule(firstId, "f", first), U64.ZERO, U64(0x3000), 1),
                    LoadEntry(LoadedModule(secondId, "g", second), U64.ZERO, U64(0x3000), 1)
                )), U64(0x3010), 0
            )

        val r1 = resolve(1, bundleA, 2, bundleB)
        val r2 = resolve(2, bundleB, 1, bundleA)
        // Deterministic regardless of snapshot entry order: lower module id always wins ties.
        assertEquals("alpha", r1.functionName)
        assertEquals("alpha", r2.functionName)
    }

    private class OrderFix(val elf: ByteArray)
    private fun orderFixture(name: String, base: Long): OrderFix {
        val root = FixDie(DwarfFixture.TAG_COMPILE_UNIT, children = listOf(
            FixDie(DwarfFixture.TAG_SUBPROGRAM, attrs = listOf(
                FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str(name)),
                FixAttr(DwarfFixture.AT_LOW_PC, DwarfFixture.FORM_ADDR, FixForm.Addr(base)),
                FixAttr(DwarfFixture.AT_HIGH_PC, DwarfFixture.FORM_DATA8, FixForm.Data8(0x40))
            ))
        ), attrs = listOf(FixAttr(DwarfFixture.AT_NAME, DwarfFixture.FORM_STRING, FixForm.Str("$name.c"))))
        val compiled = compileUnit(root)
        val info = dwarf32Unit(dwarf4CuHeader() + compiled.infoBody)
        val w = ElfWriter()
        w.addSection(".text", type = 1, flags = 6, addr = base, data = ByteArray(0x1000), addralign = 16)
        w.addSection(".debug_info", data = info)
        w.addSection(".debug_abbrev", data = compiled.abbrev)
        w.addLoadSegment(offset = base, vaddr = base, filesz = 0x1000)
        return OrderFix(w.build())
    }
}
