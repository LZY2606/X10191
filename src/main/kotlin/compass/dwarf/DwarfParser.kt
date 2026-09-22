package compass.dwarf

import compass.elf.ElfFile
import compass.model.ParsedDwarf
import compass.model.ParseIssue

/** Top-level DWARF analysis: walks .debug_info, then runs each CU's line program. */
object DwarfParser {
    fun parse(elf: ElfFile): ParsedDwarf {
        val sections = DwarfSections.from(elf)
        val issues = ArrayList<ParseIssue>()
        val tableVersions = LinkedHashMap<String, String>()

        val infoResult = if (sections.info != null) {
            InfoParser.parse(sections.info, sections)
        } else {
            issues.add(ParseIssue(".debug_info", 0, "error", "section missing; only ELF-level facts are trustworthy"))
            InfoParser.Result(emptyList(), emptyList(), emptyList(), emptyMap(), emptyMap())
        }
        issues.addAll(infoResult.issues)

        val rows = ArrayList<compass.model.LineRow>()
        val cuFiles = HashMap<Int, List<String>>()
        var sawLine4 = false
        var sawLine5 = false
        for (cu in infoResult.units) {
            val stmt = cu.stmtList ?: continue
            val lineData = sections.line
            if (lineData == null) {
                issues.add(ParseIssue(".debug_line", cu.offset, "warning",
                    "CU ${cu.index} references .debug_line but section is missing; line conclusions unavailable"))
                continue
            }
            val res = LineProgram.execute(lineData, stmt.toInt(), sections.bigEndian, sections, cu.index)
            rows.addAll(res.rows)
            issues.addAll(res.issues)
            cuFiles[cu.index] = res.files
            if (res.headerVersion >= 5) sawLine5 = true else if (res.headerVersion > 0) sawLine4 = true
        }
        if (sawLine4 && sawLine5) tableVersions["line"] = "DWARF4+DWARF5"
        else if (sawLine5) tableVersions["line"] = "DWARF5"
        else if (sawLine4) tableVersions["line"] = "DWARF4"

        val usesRnglists = infoResult.units.any { it.version >= 5 } && sections.rnglists != null
        val usesRanges = sections.ranges != null
        if (usesRnglists && usesRanges) tableVersions["ranges"] = "ranges+rnglists"
        else if (usesRnglists) tableVersions["ranges"] = "rnglists"
        else if (usesRanges) tableVersions["ranges"] = "debug_ranges"

        if (sections.str != null) tableVersions["strings"] = ".debug_str"
        if (sections.lineStr != null) tableVersions["strings"] = (tableVersions["strings"]?.plus("+") ?: "") + ".debug_line_str"
        if (sections.strOffsets != null) tableVersions["strings"] = (tableVersions["strings"]?.plus("+") ?: "") + ".debug_str_offsets"

        return ParsedDwarf(infoResult.units, infoResult.dies, rows, issues, tableVersions, cuFiles)
    }
}
