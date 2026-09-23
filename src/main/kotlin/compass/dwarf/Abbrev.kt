package compass.dwarf

import compass.elf.ByteReader
import compass.elf.EndOfDataException

data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<Pair<Int, Int>>)

/**
 * 解析 .debug_abbrev / .debug_abbrev.dwo。
 * abbrev code 0 结束一张表；attr (0,0) 结束一条声明。
 * 每个 CU 的 abbrev_offset 处开始独立读取一份（多 CU 共享时内容相同）。
 */
object AbbrevParser {
    fun parseTable(bytes: ByteArray?, offset: Long, littleEndian: Boolean): Pair<Map<Long, AbbrevDecl>, List<ParseNotice>> {
        val notices = mutableListOf<ParseNotice>()
        if (bytes == null) {
            notices += ParseNotice("error", ".debug_abbrev", offset, "section missing")
            return emptyMap<Long, AbbrevDecl>() to notices
        }
        if (offset < 0 || offset >= bytes.size) {
            notices += ParseNotice("error", ".debug_abbrev", offset, "abbrev table offset out of section")
            return emptyMap<Long, AbbrevDecl>() to notices
        }
        val r = ByteReader(bytes, littleEndian, offset.toInt(), bytes.size - offset.toInt())
        val map = LinkedHashMap<Long, AbbrevDecl>()
        try {
            while (r.remaining() > 0) {
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val child = r.u8()
                val attrs = ArrayList<Pair<Int, Int>>()
                while (true) {
                    val at = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (at == 0 && form == 0) break
                    attrs += at to form
                }
                map[code] = AbbrevDecl(code, tag, child == 1, attrs)
            }
        } catch (e: EndOfDataException) {
            notices += ParseNotice("warn", ".debug_abbrev", offset + r.pos, "truncated abbrev table: ${e.message}")
        }
        return map to notices
    }
}
