package compass.dwarf

/**
 * Second pass over a parsed CU: resolves indirect forms (strx/addrx) using the
 * CU's own base attributes, extracts CU-level attributes, and provides bounded
 * reference following for name resolution.
 */
class CuAttributeResolver(
    private val sections: DebugSections,
    private val cu: CompilationUnit,
) {
    private val dieByOffset = HashMap<Long, Die>()
    private var notedMissingStrOffsets = false
    private var notedMissingAddr = false

    fun resolve() {
        val root = cu.root ?: return
        collect(root)
        // First: CU base attributes needed to resolve indirect forms elsewhere.
        cu.addrBase = uintAttr(root, Attr.ADDR_BASE) ?: 0L
        cu.strOffsetsBase = uintAttr(root, Attr.STR_OFFSETS_BASE) ?: 0L
        cu.rnglistsBase = uintAttr(root, Attr.RNGLISTS_BASE) ?: 0L
        // Resolve indirect forms across the tree.
        for (die in dieByOffset.values) resolveDieAttrs(die)
        // CU-level attributes.
        cu.name = stringAttr(root, Attr.NAME)
        cu.compDir = stringAttr(root, Attr.COMP_DIR)
        cu.producer = stringAttr(root, Attr.PRODUCER)
        cu.dwoName = stringAttr(root, Attr.DWO_NAME)
        cu.stmtList = when (val v = root.attr(Attr.STMT_LIST)) {
            is AttrValue.SecOffset -> v.v
            is AttrValue.UInt -> v.v
            else -> null
        }
        cu.lowPc = addrAttr(root, Attr.LOW_PC)
        cu.rangesOffset = root.attr(Attr.RANGES)
        if (cu.dwoName != null && sections.get(".debug_info.dwo") == null) {
            cu.notes.add("split DWARF: skeleton CU references dwo '${cu.dwoName}' but no .debug_*.dwo sections are present; " +
                "line/address conclusions from this CU are not trustworthy")
        }
    }

    private fun collect(die: Die) {
        dieByOffset[die.offset] = die
        for (c in die.children) collect(c)
    }

    private fun resolveDieAttrs(die: Die) {
        for ((attr, value) in die.attrs) {
            when (value) {
                is AttrValue.StrIndex -> {
                    val s = resolveStrIndex(value.index)
                    if (s != null) die.attrs[attr] = AttrValue.Str(s)
                }
                is AttrValue.AddrIndex -> {
                    val a = resolveAddrIndex(value.index)
                    if (a != null) die.attrs[attr] = AttrValue.Addr(a)
                }
                is AttrValue.Strp -> {
                    val s = readCString(".debug_str", value.offset)
                    if (s != null) die.attrs[attr] = AttrValue.Str(s)
                    else die.attrs[attr] = AttrValue.Unknown(Form.STRP)
                }
                is AttrValue.LineStrp -> {
                    val s = readCString(".debug_line_str", value.offset)
                    if (s != null) die.attrs[attr] = AttrValue.Str(s)
                    else die.attrs[attr] = AttrValue.Unknown(Form.LINE_STRP)
                }
                else -> {}
            }
        }
    }

    private fun resolveStrIndex(index: Long): String? {
        val table = sections.get(".debug_str_offsets")
        if (table == null) {
            if (!notedMissingStrOffsets) {
                cu.notes.add("DW_FORM_strx used but .debug_str_offsets is missing (split DWARF?); affected strings unresolved")
                notedMissingStrOffsets = true
            }
            return null
        }
        val entrySize = if (cu.isDwarf64) 8 else 4
        val pos = cu.strOffsetsBase + index * entrySize
        if (pos < 0 || pos + entrySize > table.size) {
            cu.notes.add("strx index $index out of bounds of .debug_str_offsets")
            return null
        }
        val r = ByteReader(table, pos.toInt(), table.size, sections.littleEndian)
        val strOff = r.uN(entrySize)
        return readCString(".debug_str", strOff)
    }

    private fun resolveAddrIndex(index: Long): Long? {
        val table = sections.get(".debug_addr")
        if (table == null) {
            if (!notedMissingAddr) {
                cu.notes.add("DW_FORM_addrx used but .debug_addr is missing (split DWARF?); affected addresses unresolved")
                notedMissingAddr = true
            }
            return null
        }
        val pos = cu.addrBase + index * cu.addressSize
        if (pos < 0 || pos + cu.addressSize > table.size) {
            cu.notes.add("addrx index $index out of bounds of .debug_addr")
            return null
        }
        val r = ByteReader(table, pos.toInt(), table.size, sections.littleEndian)
        return r.uN(cu.addressSize)
    }

    fun readCString(section: String, offset: Long): String? {
        val bytes = sections.get(section) ?: return null
        if (offset < 0 || offset >= bytes.size) return null
        var end = offset.toInt()
        while (end < bytes.size && bytes[end].toInt() != 0) end++
        return String(bytes, offset.toInt(), end - offset.toInt(), Charsets.UTF_8)
    }

    fun stringAttr(die: Die, attr: Int): String? = when (val v = die.attr(attr)) {
        is AttrValue.Str -> v.s
        else -> null
    }

    fun uintAttr(die: Die, attr: Int): Long? = when (val v = die.attr(attr)) {
        is AttrValue.UInt -> v.v
        is AttrValue.SInt -> v.v
        is AttrValue.SecOffset -> v.v
        is AttrValue.Flag -> if (v.v) 1L else 0L
        else -> null
    }

    fun addrAttr(die: Die, attr: Int): Long? = when (val v = die.attr(attr)) {
        is AttrValue.Addr -> v.v
        else -> null
    }

    /** Follows abstract_origin/specification/concrete_origin chains with cycle + depth bounds. */
    fun resolveName(die: Die): String? {
        var current: Die? = die
        val visited = HashSet<Long>()
        var hops = 0
        while (current != null && hops < Limits.MAX_REF_FOLLOW) {
            if (!visited.add(current.offset)) break
            val direct = stringAttr(current, Attr.NAME)
                ?: stringAttr(current, Attr.LINKAGE_NAME)
                ?: stringAttr(current, Attr.MIPS_LINKAGE_NAME)
            if (direct != null) return direct
            val ref = (current.attr(Attr.ABSTRACT_ORIGIN) as? AttrValue.Ref)
                ?: (current.attr(Attr.SPECIFICATION) as? AttrValue.Ref)
                ?: (current.attr(Attr.CONCRETE_ORIGIN) as? AttrValue.Ref)
            if (ref == null) return null
            val target = dieByOffset[ref.offset]
            if (target == null) {
                cu.notes.add("DIE 0x${current.offset.toString(16)}: reference to 0x${ref.offset.toString(16)} does not resolve in this CU")
                return null
            }
            current = target
            hops++
        }
        return null
    }

    fun dieAt(offset: Long): Die? = dieByOffset[offset]
}
