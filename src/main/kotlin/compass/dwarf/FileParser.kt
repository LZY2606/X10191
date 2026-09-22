package compass.dwarf

import compass.elf.ElfFile

/** Orchestrates parsing one ELF file into a [ParsedFile]. */
object FileParser {
    fun parse(id: Long, elf: ElfFile): ParsedFile {
        val sections = DwarfSections(elf)
        val issues = mutableListOf<ParseIssue>()
        val ctx = ParseContext(sections)
        val infoSection = elf.dwarfSection(".debug_info")
        if (infoSection == null) {
            issues.add(ParseIssue("warning", "file", "no .debug_info: ELF loaded without DWARF DIEs"))
            return ParsedFile(id, elf, sections, ctx, emptyList(), issues)
        }
        val info = compass.elf.ByteReader(infoSection.data)
        val isDwo = elf.dwarfSection(".debug_info.dwo") != null ||
            elf.dwarfSection(".debug_abbrev.dwo") != null || isLikelyDwo(elf)

        val units = try {
            InfoParser(ctxWith(ctx, info), id, isDwo).parse()
        } catch (e: Exception) {
            issues.add(ParseIssue("error", ".debug_info", e.message ?: e.javaClass.simpleName))
            emptyList()
        }
        val parsed = ParsedFile(id, elf, sections, ctx, units, issues)
        extractScopes(parsed)
        return parsed
    }

    private fun ctxWith(ctx: ParseContext, info: compass.elf.ByteReader): ParseContext {
        // ParseContext.info is derived from sections; for a .dwo-style file the
        // fixture builder names sections with suffixes handled in DwarfSections.
        return ctx
    }

    private fun isLikelyDwo(elf: ElfFile): Boolean {
        // Plain .o with split CU DW_AT_dwo_name is still an object file; a standalone
        // dwo typically has .debug_info.dwo OR no .debug_line. Heuristic: both absent.
        return elf.dwarfSection(".debug_info.dwo") != null
    }

    private fun extractScopes(parsed: ParsedFile) {
        for (unit in parsed.units) {
            if (unit.root.tag == 0) continue
            walk(unit.root, unit, parsed, depth = 0)
        }
    }

    private fun walk(die: DieNode, unit: CompUnit, parsed: ParsedFile, depth: Int) {
        if (die.isScopeWithCode) {
            val ranges = try {
                RangeExtractor.rangesFor(die, unit, parsed)
            } catch (e: Exception) {
                unit.issues.add(ParseIssue("error", "die+${die.offset}",
                    "range extraction failed: ${e.message}"))
                emptyList()
            }
            val inlineDepth = if (die.tag == DW.TAG_inlined_subroutine) {
                var d = 0
                var p = die.parent
                while (p != null) {
                    if (p.isScopeWithCode) d++
                    p = p.parent
                }
                d
            } else 0
            if (ranges.isNotEmpty() || die.tag == DW.TAG_inlined_subroutine) {
                parsed.scopes.add(ScopeDie(unit, die, ranges, inlineDepth))
            }
        }
        for (child in die.children) walk(child, unit, parsed, depth + 1)
    }
}
