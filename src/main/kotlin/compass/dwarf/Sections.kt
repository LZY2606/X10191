package compass.dwarf

import compass.elf.ElfFile

/**
 * 从 ELF 收集调试 section。支持 .zdebug_ 的非压缩/压缩识别：
 * 本项目 fixture 使用未压缩字节；遇到 zlib 头会给出明确 warning 而不是伪造解析。
 */
class SectionSet(val blobs: Map<String, SectionBlob>, val warnings: MutableList<String> = mutableListOf()) {
    fun blob(name: String): SectionBlob? = blobs[name]

    /** GNU 风格 .zdebug 仅存在压缩标记时的诊断。 */
    fun detectCompressed() {
        blobs.keys.filter { it.startsWith(".zdebug_") }.forEach { name ->
            val b = blobs[name]?.bytes
            if (b != null && b.size >= 2 && b[0] == 'Z'.code.toByte() && b[1] == 'L'.code.toByte()) {
                warnings.add("section $name is zlib-compressed; decompress before import (raw bytes preserved, not interpreted)")
            }
        }
    }
}

object SectionExtractor {
    fun extract(elf: ElfFile): SectionSet {
        val map = linkedMapOf<String, SectionBlob>()
        val warnings = mutableListOf<String>()
        for (s in elf.debugSections()) {
            if (s.offset < 0 || s.size < 0 || s.offset > Int.MAX_VALUE.toLong() || s.size > Int.MAX_VALUE.toLong()) continue
            val safeLen = if (s.offset + s.size <= elf.raw.size) s.size.toInt() else (elf.raw.size - s.offset).toInt().coerceAtLeast(0)
            if (safeLen == 0) {
                map[s.name] = SectionBlob(s.name, s.addr, ByteArray(0))
                continue
            }
            val copy = elf.raw.copyOfRange(s.offset.toInt(), s.offset.toInt() + safeLen)
            if (safeLen < s.size) warnings.add("section ${s.name} truncated: header=${s.size} available=$safeLen")
            map[s.name] = SectionBlob(s.name, s.addr, copy)
        }
        val set = SectionSet(map, warnings)
        set.detectCompressed()
        return set
    }

    /** 便于测试：直接用 section 名 -> 字节 构造（不经过 ELF）。 */
    fun fromBlobs(blobs: Map<String, ByteArray>): SectionSet {
        val map = linkedMapOf<String, SectionBlob>()
        blobs.forEach { (k, v) -> map[k] = SectionBlob(k, 0L, v) }
        return SectionSet(map)
    }
}

/** section 原始字节摘要（入库保存，证明解析基于的字节）。 */
data class SectionDigest(
    val name: String,
    val size: Int,
    val sha256: String,
    val head16Hex: String,
    val elfAddr: Long,
)

object Digest {
    private val HEX = "0123456789abcdef".toCharArray()
    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            sb.append(HEX[(x.toInt() ushr 4) and 0xf]); sb.append(HEX[x.toInt() and 0xf])
        }
        return sb.toString()
    }

    fun sha256(b: ByteArray): String =
        hex(java.security.MessageDigest.getInstance("SHA-256").digest(b))

    fun of(blob: SectionBlob): SectionDigest =
        SectionDigest(
            blob.name, blob.size, sha256(blob.bytes),
            hex(blob.bytes.copyOfRange(0, minOf(16, blob.bytes.size))),
            blob.addr,
        )
}
