package compass

/**
 * 手工构造 DWARF section 的测试夹具。全部小端，32 位 unit length（DWARF_32）。
 * 地址宽度默认 8。目标不是生成真实编译器输出，而是精确控制每种边界情形：
 * special opcode、end_sequence、多 sequence、high_pc 两义、零长度/重叠范围、
 * 重定位、缺 dwo、未知 form、越界引用。
 */

object D {
    // tags
    const val CU = 0x11; const val SUB = 0x2e; const val INL = 0x1d
    // attributes
    const val NAME = 0x03; const val STMT = 0x10; const val LOW = 0x11; const val HIGH = 0x12
    const val COMP_DIR = 0x1b; const val RANGES = 0x55; const val ORIGIN = 0x31
    const val CALL_FILE = 0x58; const val CALL_LINE = 0x59; const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b; const val INLINE = 0x20; const val DWO_NAME = 0x76
    const val DWO_ID = 0x77; const val STR_BASE = 0x72; const val LANGUAGE = 0x13
    // forms
    const val F_ADDR = 0x01; const val F_DATA1 = 0x0b; const val F_DATA2 = 0x05
    const val F_DATA4 = 0x06; const val F_DATA8 = 0x07; const val F_STRING = 0x08
    const val F_STRP = 0x0e; const val F_SECOFF = 0x17; const val F_REF4 = 0x13
    const val F_UDATA = 0x0f; const val F_STRX = 0x1a; const val F_ADDRX = 0x1b
    const val F_RNGLISTX = 0x23; const val F_LINE_STRP = 0x1f; const val F_UNKNOWN = 0x7777
}

/** .debug_abbrev：声明按 code 1..n 顺序写入，以 0 结束整个表。 */
fun abbrevSection(vararg decls: AbbrevDeclF): ByteArray {
    val b = Bin()
    decls.forEachIndexed { i, d ->
        b.uleb((i + 1).toLong())
        b.uleb(d.tag.toLong())
        b.u8(if (d.children) 1 else 0)
        for ((a, f) in d.attrs) { b.uleb(a.toLong()); b.uleb(f.toLong()) }
        b.uleb(0); b.uleb(0)
    }
    b.uleb(0)
    return b.build()
}

data class AbbrevDeclF(val tag: Int, val children: Boolean, val attrs: List<Pair<Int, Int>>) {
    companion object { fun of(tag: Int, children: Boolean, vararg attrs: Pair<Int, Int>) =
        AbbrevDeclF(tag, children, attrs.toList()) }
}

/** 32 位 DWARF unit：4 字节长度（不含自身）+ 体。 */
fun unit32(body: ByteArray, vararg header: Int): ByteArray {
    val h = Bin(); header.forEach { h.u16(it) }
    val total = h.build().size + body.size
    return Bin().u32(total.toLong()).bytes(h.build()).bytes(body).build()
}

fun unit32Raw(prefix: ByteArray, body: ByteArray): ByteArray =
    Bin().u32((prefix.size + body.size).toLong()).bytes(prefix).bytes(body).build()

/** .debug_str：返回 (字节, 每个命名串的偏移)。 */
fun strSection(vararg s: String): Pair<ByteArray, Map<String, Long>> {
    val b = Bin().u8(0)
    val offs = LinkedHashMap<String, Long>()
    for (x in s) { offs[x] = b.size.toLong(); b.str(x) }
    return b.build() to offs
}
