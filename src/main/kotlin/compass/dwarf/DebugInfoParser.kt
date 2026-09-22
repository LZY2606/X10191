package compass.dwarf

import compass.elf.ElfFile
import compass.elf.ElfParser
import java.security.MessageDigest

/**
 * 顶层入口：导入一个 ELF（可执行文件或分离调试文件），保存原始字节摘要，
 * 解析 section 地图、CU、行程序。从不调用任何外部调试器/addr2line。
 */
object DebugInfoParser {
    private val WANTED_SECTIONS = listOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str",
        ".debug_str", ".debug_str_offsets", ".debug_ranges", ".debug_rnglists",
        ".debug_addr", ".debug_loclists", ".debug_cu_index", ".debug_tu_index",
        ".gnu_debugaltlink", ".gnu_debuglink"
    )

    fun parse(bytes: ByteArray): ParsedDebugInfo {
        val elf = ElfParser.parse(bytes)
        val warnings = ArrayList<String>()
        val digests = LinkedHashMap<String, String>()
        val sections = ArrayList<SectionInfo>()
        for (name in WANTED_SECTIONS) {
            val sec = elf.section(name)
            if (sec == null) {
                sections.add(SectionInfo(name, 0, 0, 0, present = false, sha256Short = null))
            } else {
                val data = try {
                    elf.sectionBytes(sec)
                } catch (e: Exception) {
                    warnings.add("section $name 字节无法读取：${e.message}")
                    ByteArray(0)
                }
                val sha = if (data.isNotEmpty()) MessageDigest.getInstance("SHA-256").digest(data) else null
                val hex = sha?.joinToString("") { "%02x".format(it) }
                if (hex != null) digests[name] = hex
                sections.add(SectionInfo(name, sec.offset, sec.size, sec.addr, true, hex?.substring(0, 12)))
            }
        }

        val info = elf.sectionBytes(".debug_info")
        val abbrev = elf.sectionBytes(".debug_abbrev")
        val line = elf.sectionBytes(".debug_line")
        val lineStr = elf.sectionBytes(".debug_line_str")
        val str = elf.sectionBytes(".debug_str")
        val strOffsets = elf.sectionBytes(".debug_str_offsets")
        val ranges = elf.sectionBytes(".debug_ranges")
        val rnglists = elf.sectionBytes(".debug_rnglists")

        val cuParser = CuParser(info, abbrev, str, ranges, rnglists, elf.endian)
        val cus = try {
            cuParser.parseAll()
        } catch (e: Exception) {
            warnings.add(".debug_info 整体解析中止：${e.message}；后续 CU 不可用")
            emptyList()
        }
        warnings += cus.flatMap { it.warnings }

        val lineParser = LineProgramParser(line, lineStr, str, strOffsets, elf.endian)
        val programs = ArrayList<LineProgram>()
        val seen = HashSet<Long>()
        for (cu in cus) {
            val stmt = cu.stmtListOffset ?: continue
            if (!seen.add(stmt)) continue
            val prog = try {
                lineParser.parseAt(stmt, cu.addressSize, cu.dwarfVersion, cu.is64Bit, cu.compDir ?: cu.name).copy(cuOffset = cu.offset)
            } catch (e: Exception) {
                warnings.add("CU @0x${cu.offset.toString(16)} 行程序解析失败：${e.message}")
                null
            }
            if (prog != null) {
                programs.add(prog)
                warnings += prog.warnings.map { "CU @0x${cu.offset.toString(16)}: $it" }
            }
        }
        // 没有 CU 引用但存在的 .debug_line unit（宽松处理 fixture）
        if (programs.isEmpty() && line != null) {
            try {
                programs.add(lineParser.parseAt(0, 8, 4, false, null))
            } catch (_: Exception) {
            }
        }

        return ParsedDebugInfo(sections, cus, programs, warnings.distinct(), digests)
    }
}
