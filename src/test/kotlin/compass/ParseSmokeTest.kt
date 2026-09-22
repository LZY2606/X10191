package compass

import compass.dwarf.DebugInfoParser
import compass.fixture.DemoFixtures
import kotlin.test.Test
import kotlin.test.assertEquals

class ParseSmokeTest {
    @Test
    fun smoke() {
        val bytes = DemoFixtures.buildFull()
        val p = DebugInfoParser.parse(bytes)
        println("CUs: " + p.cus.size)
        p.cus.forEach { cu ->
            println("CU @%x v%d unit=%s degraded=%s name=%s dwo=%s dies=%d warns=%s".format(
                cu.offset, cu.dwarfVersion, cu.unitType, cu.degraded, cu.name, cu.dwoName, cu.dies.size, cu.warnings))
        }
        p.programs.forEach { pr ->
            println("LINE cu=%x v%d rows=%d seqs=%d".format(pr.cuOffset, pr.table.dwarfVersion, pr.rows.size, pr.rows.count{it.endSequence}))
            pr.rows.forEach { r -> println("   [%d] %x %s:%d:%d stmt=%s end=%s".format(r.hseq, r.address, pr.fileName(r.fileIndex), r.line, r.column, r.isStmt, r.endSequence)) }
            pr.warnings.forEach { println("   WARN $it") }
        }
        println("global warnings: " + p.warnings)
        assertEquals(4, p.cus.size)
    }
}
