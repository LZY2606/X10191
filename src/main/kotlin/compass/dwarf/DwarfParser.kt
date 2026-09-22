package compass.dwarf

/** 顶层入口：ELF -> sections -> abbrev -> info/CU -> line programs，聚合全部诊断。 */
object DwarfParser {
    fun parse(file: ByteArray): ParseResult {
        val (elf, sectionBytes, elfDiags) = ElfParser(file).parse()
        val (abbrev, abbrevDiags) = AbbrevParser.parse(sectionBytes[".debug_abbrev"])
        val infoParser = InfoParser(sectionBytes, abbrev, LineParser())
        val units = try {
            infoParser.parse()
        } catch (e: CursorException) {
            listOf<CompileUnit>()
        }
        val diags = mutableListOf<Diagnostic>()
        diags += elfDiags
        diags += abbrevDiags
        diags += infoParser.allDiagnostics()
        if (sectionBytes[".debug_info"] == null) {
            diags += Diagnostic("INFO", "info", "无 .debug_info 节")
        }
        if (sectionBytes[".debug_abbrev"] == null) {
            diags += Diagnostic("ERROR", "abbrev", "无 .debug_abbrev 节")
        }
        units.forEach { diags += it.diagnostics }
        units.forEach { u -> u.lineProgram?.let { diags += it.diagnostics } }
        if (units.none { it.dwoName == null }) {
            // 全部 CU 都依赖 dwo
        }
        val missingDwo = units.mapNotNull { it.dwoName }.distinct()
        for (name in missingDwo) {
            diags += Diagnostic("WARNING", "split-dwarf", "骨架 CU 指向分离调试文件 '$name'，本次导入未提供 dwo；骨架范围内的地址/行号仍可信，dwo 内联细节不可用")
        }
        return ParseResult(elf, units, diags, sectionBytes)
    }
}
