package compass.dwarf

import compass.elf.BinaryParseException
import compass.elf.Reader
import java.nio.ByteOrder

/** abbrev 表：code -> 声明；code 0 是表结束。 */
class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<Pair<Int, Int>>
)

object AbbrevParser {
    /** 从 .debug_abbrev 的 [offset] 解析一张 abbrev 表，直到 code=0。 */
    fun parseTable(debugAbbrev: ByteArray?, offset: Long, endian: ByteOrder): Map<Long, AbbrevDecl> {
        if (debugAbbrev == null) throw BinaryParseException("缺少 .debug_abbrev section")
        if (offset < 0 || offset >= debugAbbrev.size) throw BinaryParseException(".debug_abbrev 偏移越界 0x${offset.toString(16)}")
        val r = Reader(debugAbbrev, endian)
        r.seek(offset.toInt())
        val map = LinkedHashMap<Long, AbbrevDecl>()
        var guard = 0
        while (true) {
            if (++guard > 100_000) throw BinaryParseException("abbrev 条目数量超限")
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.uleb().toInt()
            val hasChildren = r.u1() == 1
            val attrs = ArrayList<Pair<Int, Int>>()
            while (true) {
                val at = r.uleb().toInt()
                val form = r.uleb().toInt()
                if (at == 0 && form == 0) break
                attrs.add(at to form)
            }
            map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
        }
        return map
    }
}
