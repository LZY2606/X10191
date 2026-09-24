package compass.model

import compass.dwarf.AddrRange
import compass.dwarf.LineRow

data class CuModel(
    val cuIndex: Int,
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val name: String?,
    val compDir: String?,
    val stmtList: Long?,
    val dwoName: String?,
    val dwoMissing: Boolean,
    val degraded: Boolean,
    val diagnostics: List<String>
)

data class DieModel(
    val cuIndex: Int,
    val offset: Long,
    val parentOffset: Long?,
    val depth: Int,
    val tag: Int,
    val name: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val highPcIsOffset: Boolean,
    val ranges: List<AddrRange>,
    val inline: Long?,
    val callFile: Long?,
    val callLine: Long?,
    val callColumn: Long?,
    val declFile: Long?,
    val declLine: Long?
) {
    fun contains(addr: Long): Boolean = ranges.any { it.contains(addr) }
    fun narrowestWidth(addr: Long): Long? =
        ranges.filter { it.contains(addr) }.minOfOrNull { it.width }
}

data class ImportModel(
    val cus: List<CuModel>,
    val dies: List<DieModel>,
    /** cuIndex -> line table */
    val lineTables: Map<Int, LineTableModel>,
    val diagnostics: List<String>
)

data class LineTableModel(
    val version: Int,
    val directories: List<String>,
    val files: List<String>,
    val rows: List<LineRow>
)
