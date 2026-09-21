package compass

import compass.fixtures.*
import compass.resolve.Workspace
import compass.store.ModuleLoad
import compass.store.Repository
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Query ordering must be stable when file import order changes, and importing a
 * new debug file version must not mutate older crash records.
 */
class OrderingAndStoreTest {

    private fun moduleBytes(name: String, baseAddr: Long, fnName: String): ByteArray {
        val f = DwarfFixture(version = 4)
        val sub = f.die(Fixtures.TAG_subprogram, listOf(
            f.lowPc(baseAddr), f.highPcOffset(0x40), f.name(fnName),
        ))
        f.beginCu(listOf(f.name(name)), listOf(sub))
        return Fixtures.elf(Fixtures.sectionsOf(f))
    }

    @Test
    fun `candidate order independent of import order`(@TempDir dir: Path) {
        val a = moduleBytes("a.c", 0x1000, "fnA")
        val b = moduleBytes("b.c", 0x2000, "fnB")

        fun runOnce(first: ByteArray, firstName: String, second: ByteArray, secondName: String): List<String> {
            val repo = Repository(dir.resolve(java.util.UUID.randomUUID().toString()))
            repo.init()
            repo.importModule(firstName, "$firstName.elf", first)
            repo.importModule(secondName, "$secondName.elf", second)
            val ws = Workspace(repo)
            // Relative-address query against module a is unaffected by import order;
            // the deterministic global comparator keys on module key/version.
            val snap = repo.createSnapshot("s", listOf(
                ModuleLoad(firstName, 1, 0L, 1, null),
                ModuleLoad(secondName, 1, 0L, 1, null),
            ))
            val merged = ws.resolveRuntime(snap, 0x1010)
            repo.close()
            return merged.map { "${it.moduleKey}:${it.scopeName}" }
        }

        val order1 = runOnce(a, "modA", b, "modB")
        val order2 = runOnce(b, "modB", a, "modA")
        // Only modA covers 0x1010; both import orders must agree.
        assertEquals(listOf("modA:fnA"), order1)
        assertEquals(listOf("modA:fnA"), order2)
    }

    @Test
    fun `importing a new version does not change old crash records`(@TempDir dir: Path) {
        val repo = Repository(dir.resolve("db"))
        repo.init()
        val v1 = moduleBytes("c.c", 0x1000, "v1fn")
        val m1 = repo.importModule("mod", "mod.elf", v1)
        assertEquals(1, m1.version)

        val snap = repo.createSnapshot("crash", listOf(ModuleLoad("mod", 1, 0L, 1, null)))
        val batch = repo.saveCrashBatch("batch-1", snap.id, "0x1010", Workspace(repo).parseAddresses("0x1010"))

        // import a strictly different binary as a new version
        val v2 = moduleBytes("c.c", 0x2000, "v2fn")
        val m2 = repo.importModule("mod", "mod.elf", v2)
        assertEquals(2, m2.version)
        assertTrue(repo.modules[m1.id]!!.superseded)
        assertFalse(repo.modules[m2.id]!!.superseded)

        // old crash record is byte-identical and still references snapshot v1
        val stored = repo.listCrashBatches().first { it.id == batch.id }
        assertEquals(listOf(0x1010L), stored.addresses)
        assertEquals("0x1010", stored.rawInput)
        val storedSnap = repo.snapshot(stored.snapshotId)!!
        assertEquals(1, storedSnap.loads.single().moduleVersion)
        repo.close()
    }

    @Test
    fun `same content re-import is idempotent`(@TempDir dir: Path) {
        val repo = Repository(dir.resolve("db2"))
        repo.init()
        val bytes = moduleBytes("c.c", 0x1000, "x")
        val a = repo.importModule("m", "m.elf", bytes)
        val b = repo.importModule("m", "m.elf", bytes)
        assertEquals(a.id, b.id)
        assertEquals(1, repo.modules.size)
        repo.close()
    }
}
