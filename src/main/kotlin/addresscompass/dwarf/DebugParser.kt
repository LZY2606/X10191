package addresscompass.dwarf

import addresscompass.elf.ElfFile
import addresscompass.elf.ElfParser
import addresscompass.elf.RawSection
import addresscompass.model.AddrRange
import addresscompass.model.CompileUnit
import addresscompass.model.DIE
import addresscompass.model.FormValue
import addresscompass.model.LineProgram
import addresscompass.model.ParseIssue
import addresscompass.model.ParsedDebug
import addresscompass.model.SectionSummary
import addresscompass.model.Severity
import addresscompass.model.Trust
import java.security.MessageDigest

object DebugParser {

    fun parse(fileName: String, bytes: ByteArray): ParsedDebug {
        val sha = sha256(bytes)
        val issues = mutableListOf<ParseIssue>()
        val elf = try {
            ElfParser.parse(bytes)
        } catch (e: Exception) {
            throw IllegalArgumentException("ELF parse failed: ${e.message}", e)
        }
        val sections = DebugSections(elf)
        val ctx = CuBuilder(sections, elf.endian, issues, isSplitFile = false)
        val cus = CuParser.parseAll(ctx)

        // Line programs
        val linePrograms = LinkedHashMap<Long, LineProgram>()
        val lineCtx = LineContext(sections.line, sections.lineStr, sections.str, elf.endian)
        for (cu in cus) {
            val stmt = cu.stmtListOffset
            if (stmt != null) {
                val lp = LineProgramParser.parseAt(lineCtx, cu.sectionOffset, stmt, cu.version)
                if (lp != null) {
                    linePrograms[cu.sectionOffset] = lp
                    issues += lp.issues
                } else {
                    issues += ParseIssue(Severity.WARNING, ".debug_line", stmt,
                        "CU ${cu.name ?: cu.key}: line program missing/unreadable", true)
                }
            }
        }

        // Range + reference/name resolution (two-phase)
        val resolver = DieResolver(sections, elf.endian, cus)
        resolver.resolveAll()
        for (cu in cus) cu.issues += resolver.takeIssues()
        issues += resolver.issuesOf()

        val summaries = elf.sections.map { rs ->
            val s = rs.summary
            s.copy(sha256 = rs.bytes?.let { sha256(it) })
        }
        val missingDwos = cus.filter { it.isSkeleton }.mapNotNull { it.dwoName }.distinct()
        val trustWorst = cus.maxOfOrNull { it.trust } ?: Trust.FULL
        if (missingDwos.isNotEmpty()) {
            issues += ParseIssue(Severity.WARNING, ".debug_info", 0,
                "skeleton CU references split debug file(s) not yet imported: $missingDwos", true)
        }

        return ParsedDebug(
            fileName = fileName, sha256 = sha,
            elfClass = if (elf.class32) 32 else 64,
            endian = if (elf.endian == java.nio.ByteOrder.LITTLE_ENDIAN) "little" else "big",
            machine = elf.machine, elfType = elf.type,
            buildId = elf.buildId, preferredBase = elf.preferredLoadBase, endOfImage = elf.endOfImage,
            sections = summaries, segments = elf.segments, cus = cus,
            linePrograms = linePrograms, issues = issues, missingDwos = missingDwos,
        )
    }

    fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}

