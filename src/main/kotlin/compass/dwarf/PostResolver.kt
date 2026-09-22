package compass.dwarf

/**
 * 第二次扫描：把 Raw.StrPtr / Raw.StrIndex / Raw.AddrIndex 解析成最终值。
 * 任何索引越界只产生诊断并返回 null，不影响其它 CU。
 */
class PostResolver(
    private val ctx: InfoParser.UnitCtx,
    private val sections: Map<String, ByteArray>,
    private val diags: MutableList<Diagnostic>
) {
    private val strSection = sections[".debug_str"]
    private val lineStrSection = sections[".debug_line_str"]
    private val strOffsets = sections[".debug_str_offsets"]
    private val addrSection = sections[".debug_addr"]

    private val strBase: Long by lazy {
        val explicit = ctx.body.let { b ->
            // root DIE 上的 DW_AT_str_offsets_base
            null
        }
        explicit ?: ctx.table.let { 0L }
    }

    fun resolveAll(dies: List<Die>) {
        dies.forEach { die ->
            die.attrs.forEach { a ->
                val v = a.value
                val resolved: Any? = when (v) {
                    is Raw.StrPtr -> readString(v.offset)
                    is Raw.StrIndex -> readStringAtOffsetIndex(v.index, die)
                    else -> v
                }
                if (resolved != v) {
                    val idx = die.attrs.indexOf(a)
                    die.attrs[idx] = a.copy(value = resolved)
                }
            }
        }
    }

    private fun readString(encoded: Long): String? {
        if (encoded < 0) {
            val off = (-encoded - 1)
            val sec = lineStrSection ?: return null.also {
                diags += Diagnostic("WARNING", "cu:${ctx.cuIndex}", "DW_FORM_line_strp 但缺 .debug_line_str")
            }
            return try { ByteView(sec).cstring(off.toInt()) } catch (e: CursorException) {
                diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "line_str 越界 off=$off"); null
            }
        }
        val sec = strSection ?: return null.also {
            diags += Diagnostic("WARNING", "cu:${ctx.cuIndex}", "DW_FORM_strp 但缺 .debug_str")
        }
        return try { ByteView(sec).cstring(encoded.toInt()) } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "str 越界 off=$encoded"); null
        }
    }

    /** str_offsets：DWARF5 基址在 DW_AT_str_offsets_base；无该属性时退回 0（GNU 风格无表头）。 */
    private fun readStringAtOffsetIndex(index: Long, die: Die): String? {
        val sec = strOffsets ?: run {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "DW_FORM_strx 但缺 .debug_str_offsets")
            return null
        }
        val base = strOffsetsBase(die)
        val size = if (ctx.is64) 8 else 4
        val at = (base + index * size).toInt()
        val strOff = try {
            val v = ByteView(sec)
            if (size == 4) v.u32(at) else v.u64(at)
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "str_offsets 越界 idx=$index")
            return null
        }
        return readString(strOff)
    }

    private fun strOffsetsBase(anyDie: Die): Long {
        // DW_AT_str_offsets_base 挂在根 DIE 上
        val root = anyDie
        root.num(0x72)?.let { return it }
        return 0L
    }

    /** addrx：DW_AT_addr_base（v5 指向表头之后）或 GNU 0x2133。 */
    fun addrAt(index: Long): Long? {
        val sec = addrSection ?: run {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "DW_FORM_addrx 但缺 .debug_addr")
            return null
        }
        val base = addrBase()
        val size = ctx.addressSize
        val at = (base + index * size).toInt()
        return try {
            val v = ByteView(sec)
            when (size) { 1 -> v.u8(at).toLong(); 2 -> v.u16(at).toLong(); 4 -> v.u32(at); 8 -> v.u64(at); else -> null }
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "addr 越界 idx=$index"); null
        }
    }

    private fun addrBase(): Long {
        // 根 DIE 查找；调用方在 rangesFor(root) 上下文中已持有 root，这里通过 table 无法拿到，
        // 因此 DwarfParser 会显式传入。本类持有惰性根：使用时由 setRoot 注入。
        return rootOverride?.num(0x73) // DW_AT_addr_base
            ?: rootOverride?.num(0x2133L.toInt())
            ?: 0L
    }

    private var rootOverride: Die? = null
    fun setRoot(root: Die?) { rootOverride = root }

    fun stringAttr(die: Die, attr: Int): String? = die.attr(attr)?.value as? String
}
