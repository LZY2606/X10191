package compass

data class ElfSection(
    val name: String, val type: Long, val flags: Long,
    val addr: Long, val offset: Long, val size: Long, val data: ByteArray
)

class ElfFile(val bits: Int, val littleEndian: Boolean, val elfType: Int, val sections: List<ElfSection>) {
    fun debugSections(): Map<String, ByteArray> =
        sections.filter { it.name.startsWith(".debug") }.associate { it.name to it.data }

    companion object {
        private const val SHT_NOBITS = 8L

        fun parse(fileBytes: ByteArray): ElfFile {
            if (fileBytes.size < 0x34 || fileBytes[0] != 0x7F.toByte() ||
                fileBytes[1] != 'E'.code.toByte() || fileBytes[2] != 'L'.code.toByte() ||
                fileBytes[3] != 'F'.code.toByte()
            ) throw ParseException("不是 ELF 文件")
            val bits = when (fileBytes[4].toInt()) { 1 -> 32; 2 -> 64; else -> throw ParseException("未知 ELF 类别") }
            val le = when (fileBytes[5].toInt()) { 1 -> true; 2 -> false; else -> throw ParseException("未知 ELF 字节序") }
            val r = BinReader(fileBytes, 0, le)
            r.seek(16)
            val elfType = r.u16()
            r.seek(if (bits == 64) 0x28 else 0x20)
            val shoff = if (bits == 64) r.u64() else r.u32()
            r.seek(if (bits == 64) 0x3A else 0x2E)
            val shentsize = r.u16()
            val shnum = r.u16()
            val shstrndx = r.u16()
            if (shoff <= 0L || shnum == 0) return ElfFile(bits, le, elfType, emptyList())
            if (shoff + shentsize.toLong() * shnum > fileBytes.size)
                throw ParseException("section 头表越界 shoff=$shoff num=$shnum")

            data class H(val nameOff: Long, val type: Long, val flags: Long, val addr: Long, val offset: Long, val size: Long)

            val headers = (0 until shnum).map { i ->
                r.seek((shoff + i.toLong() * shentsize).toInt())
                if (bits == 64) H(r.u32(), r.u32(), r.u64(), r.u64(), r.u64(), r.u64())
                else H(r.u32(), r.u32(), r.u32(), r.u32(), r.u32(), r.u32())
            }
            val strH = headers.getOrNull(shstrndx) ?: throw ParseException("shstrtab 索引越界")
            if (strH.offset < 0 || strH.offset + strH.size > fileBytes.size)
                throw ParseException("shstrtab 数据越界")
            val strEnd = (strH.offset + strH.size).toInt()

            fun nameAt(off: Long): String {
                var p = (strH.offset + off).toInt()
                if (p < strH.offset.toInt() || p >= strEnd) return ""
                val sb = StringBuilder()
                while (p < strEnd && fileBytes[p] != 0.toByte()) {
                    sb.append(fileBytes[p].toInt().toChar()); p++
                }
                return sb.toString()
            }

            val sections = headers.map { h ->
                val end = h.offset + h.size
                if (h.type != SHT_NOBITS && h.size > 0 && (h.offset < 0 || end > fileBytes.size || end < h.offset))
                    throw ParseException("section 数据越界 offset=${h.offset} size=${h.size}")
                val data = if (h.type == SHT_NOBITS || h.size == 0L) ByteArray(0)
                else fileBytes.copyOfRange(h.offset.toInt(), end.toInt())
                ElfSection(nameAt(h.nameOff), h.type, h.flags, h.addr, h.offset, h.size, data)
            }
            return ElfFile(bits, le, elfType, sections)
        }
    }
}
