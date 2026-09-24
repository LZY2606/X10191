package compass.dwarf

/** Result of parsing one debug object: units, DIE index and trust information. */
class DwarfBundle(
    val sections: DwarfSections,
    val units: List<CompUnit>,
    val diesByOffset: Map<Long, DIE>,
    val linePrograms: Map<Long, LineProgram>,
    /** Section names that failed parsing and why — conclusions from them are NOT trusted. */
    val corruptSections: Map<String, String>,
    val warnings: List<String>,
) {
    fun unitAtHeader(offset: Long): CompUnit? = units.firstOrNull { it.headerOffset == offset }
    fun dieAt(offset: Long): DIE? = diesByOffset[offset]
    fun lineFor(cu: CompUnit): LineProgram? {
        val stmt = cu.root.attrValue(DW.AT.stmt_list)
        val off = (stmt as? AttrValue.SectionOffset)?.offset ?: return null
        return linePrograms[off]
    }
}
