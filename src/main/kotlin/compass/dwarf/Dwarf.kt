package compass.dwarf

/** Orchestrates parsing of all DWARF sections of one imported file. */
object Dwarf {
    fun parse(sections: List<SectionInfo>, elfWarnings: List<String> = emptyList()): ParsedFile {
        val warnings = ArrayList<String>()
        warnings.addAll(elfWarnings)
        val cus = ArrayList<ParsedCu>()

        val info = sections.firstOrNull { it.name == ".debug_info" }
        if (info != null) {
            val set = SectionSet(sections, preferDwo = false)
            cus.addAll(InfoParser.parse(info.data, set, fromDwo = false, fileWarnings = warnings))
        } else {
            warnings.add("no .debug_info section")
        }

        val dwoInfo = sections.firstOrNull { it.name == ".debug_info.dwo" }
        if (dwoInfo != null) {
            val set = SectionSet(sections, preferDwo = true)
            cus.addAll(InfoParser.parse(dwoInfo.data, set, fromDwo = true, fileWarnings = warnings))
        }

        return ParsedFile(sections, cus, warnings)
    }
}
