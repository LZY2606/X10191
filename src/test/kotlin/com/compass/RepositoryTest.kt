package com.compass

import com.compass.dwarf.*
import com.compass.store.*
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RepositoryTest {
    private val dbFile = File("build/tmp/test-compass-${System.nanoTime()}.db")
    private val db = Database(dbFile.absolutePath)
    private val repo = Repository(db)
    private val queries = QueryService(repo)

    @AfterTest fun cleanup() { db.close() }

    private fun mainBytes(): ByteArray {
        val b = ElfBuilder().text(ByteArray(0x300))
        DwarfFixtures.dwarf4().map.forEach { (n, d) -> b.debug(n, d) }
        return b.build()
    }

    @Test
    fun importCreatesVersionAndQueryResolvesWithBias() {
        val v = repo.createVersion("v1")
        repo.importFile(v, "main.elf", mainBytes(), "main")
        val crash = repo.createCrash(v, "crash-a")
        val linkBase = 0x401000L
        // bias chosen so that runtime INL maps straight back to relative INL
        val bias = 0x1000_0000L
        val runtimeBase = linkBase + bias
        val runtime = DwarfFixtures.INL_LO + bias
        val load = repo.addModuleLoad(crash, "main", null, Repository.hex(runtimeBase))
        assertEquals(bias, load.bias)
        val results = queries.resolve(v, Repository.hex(runtime), crash)
        val top = results.single().candidates.first()
        assertEquals("inner_inline", top.functionName)
        assertEquals(Repository.hex(load.bias), results.single().loadBias)
    }

    @Test
    fun multipleGenerationsKeepSnapshotsPinned() {
        val v = repo.createVersion("vgen")
        repo.importFile(v, "main.elf", mainBytes(), "main")
        val crash = repo.createCrash(v, "crash-g")
        val g1 = repo.addModuleLoad(crash, "main", null, "0x555500000000")
        val g2 = repo.addModuleLoad(crash, "main", null, "0x7fff00000000")
        assertEquals(1, g1.generation); assertEquals(2, g2.generation)
        assertNotEquals(g1.bias, g2.bias)
        // Querying both generations returns the same relative resolution.
        val rt1 = g1.runtimeBase + (DwarfFixtures.INL_LO - 0x401000L)
        val rt2 = g2.runtimeBase + (DwarfFixtures.INL_LO - 0x401000L)
        val r1 = queries.resolve(v, Repository.hex(rt1), crash, 1).single()
        val r2 = queries.resolve(v, Repository.hex(rt2), crash, 2).single()
        assertEquals(r1.relativeAddress, r2.relativeAddress)
        assertEquals("inner_inline", r1.candidates.first().functionName)
    }

    @Test
    fun importingNewFileMakesNewVersionWithoutTouchingOldCrash() {
        val v1 = repo.createVersion("old")
        repo.importFile(v1, "main.elf", mainBytes(), "main")
        val crash = repo.createCrash(v1, "old-crash")
        repo.addModuleLoad(crash, "main", null, "0x555500000000")

        val v2 = repo.createVersion("new")
        // Import a slightly different object (different text base => different file).
        val b = ElfBuilder().text(ByteArray(0x300), 0x601000)
        DwarfFixtures.dwarf4().map.forEach { (n, d) -> b.debug(n, d) }
        repo.importFile(v2, "main2.elf", b.build(), "main")

        val oldCrash = repo.crashes().single { it.id == crash }
        assertEquals(v1, oldCrash.versionId)
        // Old version bundle still resolves independently.
        assertTrue(repo.bundle(v1) != null && repo.bundle(v2) != null)
    }

    @Test
    fun batchQueryHandlesMixedSeparators() {
        val v = repo.createVersion("vb")
        repo.importFile(v, "m", mainBytes(), "main")
        val addresses = listOf(
            DwarfFixtures.INL_LO + 2, DwarfFixtures.FUNC_LO + 4, DwarfFixtures.INL_HI + 1
        ).joinToString("\n") { Repository.hex(it) }
        val rel = queries.resolveRelative(v, Repository.hex(DwarfFixtures.INL_LO + 2), null)
        assertTrue(rel.candidates.first().functionName == "inner_inline")
    }
}
