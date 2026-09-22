package compass.dwarf

class UnknownFormException(val form: Int, msg: String) : DwarfException(msg)

data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long = 0)
data class AbbrevEntry(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

object AbbrevTable {
    fun parse(reader: Reader, offset: Long, limits: DwarfLimits): Map<Long, AbbrevEntry> {
        if (offset < 0 || offset >= reader.size) throw DwarfException("abbrev offset 0x${offset.toString(16)} out of bounds")
        val r = reader.cloneAt(offset.toInt())
        val out = LinkedHashMap<Long, AbbrevEntry>()
        while (true) {
            if (out.size >= limits.maxAbbrevs) throw DwarfException("abbrev table too large")
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.uleb().toInt()
            val hasChildren = r.u8() != 0
            val attrs = mutableListOf<AbbrevAttr>()
            while (true) {
                if (attrs.size >= limits.maxAbbrevAttrs) throw DwarfException("abbrev attribute list too long")
                val name = r.uleb().toInt()
                val form = r.uleb().toInt()
                if (name == 0 && form == 0) break
                val implicit = if (form == Form.IMPLICIT_CONST) r.sleb() else 0L
                attrs += AbbrevAttr(name, form, implicit)
            }
            out[code] = AbbrevEntry(code, tag, hasChildren, attrs)
        }
        return out
    }
}

/** Reads one attribute value of the given form; throws UnknownFormException for forms it cannot size. */
fun readFormValue(
    r: Reader, form0: Int, addrSize: Int, version: Int, limits: DwarfLimits, depth: Int = 0,
): Pair<Int, AttrValue> {
    var form = form0
    if (form == Form.INDIRECT) {
        if (depth >= limits.maxIndirectDepth) throw DwarfException("DW_FORM_indirect nesting too deep")
        form = r.uleb().toInt()
        if (form == Form.INDIRECT) throw DwarfException("DW_FORM_indirect chain")
    }
    val v: AttrValue = when (form) {
        Form.ADDR -> AttrValue.Addr(r.addr(addrSize))
        Form.BLOCK1 -> AttrValue.Block(r.bytes(r.u8()))
        Form.BLOCK2 -> AttrValue.Block(r.bytes(r.u16()))
        Form.BLOCK4 -> AttrValue.Block(r.bytes(r.u32().toInt()))
        Form.BLOCK -> AttrValue.Block(r.bytes(r.uleb().toInt()))
        Form.DATA1 -> AttrValue.Data(r.u8().toLong())
        Form.DATA2 -> AttrValue.Data(r.u16().toLong())
        Form.DATA4 -> AttrValue.Data(r.u32())
        Form.DATA8 -> AttrValue.Data(r.u64())
        Form.UDATA -> AttrValue.Data(r.uleb())
        Form.SDATA -> AttrValue.SData(r.sleb())
        Form.DATA16 -> AttrValue.Block(r.bytes(16))
        Form.STRING -> AttrValue.Str(r.cstring())
        Form.STRP -> AttrValue.StrRef(r.offset(), "str")
        Form.LINE_STRP -> AttrValue.StrRef(r.offset(), "line_str")
        Form.STRP_SUP, Form.GNU_STRP_ALT -> AttrValue.StrRef(r.offset(), "sup")
        Form.FLAG -> AttrValue.Flag(r.u8() != 0)
        Form.FLAG_PRESENT -> AttrValue.Flag(true)
        Form.REF1 -> AttrValue.Ref(r.u8().toLong())
        Form.REF2 -> AttrValue.Ref(r.u16().toLong())
        Form.REF4 -> AttrValue.Ref(r.u32())
        Form.REF8 -> AttrValue.Ref(r.u64())
        Form.REF_UDATA -> AttrValue.Ref(r.uleb())
        Form.REF_ADDR -> AttrValue.Ref(if (version <= 2) r.addr(addrSize) else r.offset())
        Form.REF_SIG8 -> AttrValue.Data(r.u64())
        Form.REF_SUP4 -> AttrValue.Data(r.u32())
        Form.REF_SUP8 -> AttrValue.Data(r.u64())
        Form.SEC_OFFSET -> AttrValue.SecOffset(r.offset())
        Form.EXPLOC -> AttrValue.Block(r.bytes(r.uleb().toInt()))
        Form.IMPLICIT_CONST -> AttrValue.SData(0) // patched by caller using abbrev implicit value
        Form.STRX -> AttrValue.Indexed("strx", r.uleb())
        Form.STRX1 -> AttrValue.Indexed("strx", r.u8().toLong())
        Form.STRX2 -> AttrValue.Indexed("strx", r.u16().toLong())
        Form.STRX3 -> AttrValue.Indexed("strx", r.u8().toLong() or (r.u8().toLong() shl 8) or (r.u8().toLong() shl 16))
        Form.STRX4 -> AttrValue.Indexed("strx", r.u32())
        Form.ADDRX -> AttrValue.Indexed("addrx", r.uleb())
        Form.ADDRX1 -> AttrValue.Indexed("addrx", r.u8().toLong())
        Form.ADDRX2 -> AttrValue.Indexed("addrx", r.u16().toLong())
        Form.ADDRX3 -> AttrValue.Indexed("addrx", r.u8().toLong() or (r.u8().toLong() shl 8) or (r.u8().toLong() shl 16))
        Form.ADDRX4 -> AttrValue.Indexed("addrx", r.u32())
        Form.RNGLISTX -> AttrValue.Indexed("rnglistx", r.uleb())
        Form.LOCLISTX -> AttrValue.Indexed("loclistx", r.uleb())
        else -> throw UnknownFormException(form, "unknown DW_FORM 0x${form.toString(16)} at 0x${r.pos.toString(16)}")
    }
    return form to v
}

object DieParser {
    /** Parse the DIE tree of one CU. On unknown form the CU is abandoned (caller skips to CU end). */
    fun parse(
        info: Reader, cuStart: Int, cuEnd: Int, abbrevs: Map<Long, AbbrevEntry>,
        addrSize: Int, version: Int, limits: DwarfLimits,
    ): Die {
        var dieCount = 0

        fun parseOne(depth: Int): Die? {
            if (depth > limits.maxDieDepth) throw DwarfException("DIE nesting exceeds ${limits.maxDieDepth}")
            if (++dieCount > limits.maxDiesPerUnit) throw DwarfException("DIE count exceeds ${limits.maxDiesPerUnit}")
            if (info.pos >= cuEnd) return null
            val dieOffset = info.pos
            val code = info.uleb()
            if (code == 0L) return null // null entry ends sibling chain
            val abbrev = abbrevs[code]
                ?: throw DwarfException("abbrev code $code not found at DIE 0x${dieOffset.toString(16)}")
            val attrs = ArrayList<DieAttr>(abbrev.attrs.size)
            for (a in abbrev.attrs) {
                val (form, value) = readFormValue(info, a.form, addrSize, version, limits)
                val patched = if (a.form == Form.IMPLICIT_CONST) AttrValue.SData(a.implicitConst) else value
                attrs += DieAttr(a.attr, form, patched)
            }
            val children = mutableListOf<Die>()
            if (abbrev.hasChildren) {
                while (true) {
                    val child = parseOne(depth + 1) ?: break
                    children += child
                }
            }
            return Die(dieOffset.toLong(), depth, abbrev.tag, attrs, children)
        }

        return parseOne(0) ?: throw DwarfException("empty compilation unit at 0x${cuStart.toString(16)}")
    }
}
