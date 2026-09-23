package compass.dwarf

import compass.util.*

// ---- DWARF constants -------------------------------------------------------

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
}

object At {
    const val NAME = 0x03
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val ABSTRACT_ORIGIN = 0x31
    const val COMP_DIR = 0x1b
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val RANGES = 0x55
    const val PRODUCER = 0x25
    const val INLINE = 0x20
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val DWO_NAME = 0x76
    const val GNU_DWO_NAME = 0x2130
    const val GNU_DWO_ID = 0x2131
    const val PRIORITY = 0x3e90 // synthetic attr space: explicit candidate priority
}

object UnitType {
    const val COMPILE = 0x01
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
}

// ---- Forms -----------------------------------------------------------------

sealed class AttrValue {
    data class Address(val v: Long) : AttrValue()
    data class Constant(val v: Long) : AttrValue()
    data class StringVal(val v: String) : AttrValue()
    data class Reference(val v: Long, val outOfBounds: Boolean = false) : AttrValue()
    data class Flag(val v: Boolean) : AttrValue()
    data class Block(val v: ByteArray) : AttrValue()
    data class SecOffset(val v: Long) : AttrValue()
    data class Strx(val index: Long) : AttrValue()
    data class Addrx(val index: Long) : AttrValue()
    data class Rnglistx(val index: Long) : AttrValue()
    data class Loclistx(val index: Long) : AttrValue()
    data class Unknown(val formCode: Int) : AttrValue()
}

data class AttrSpec(val name: Int, val form: Int, val implicitConst: Long = 0L)

data class Abbrev(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AttrSpec>)

object F {
    const val ADDR = 0x01
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val DATA2 = 0x05
    const val BLOCK1 = 0x06
    const val DATA1 = 0x07
    const val STRING = 0x08
    const val BLOCK = 0x09
    const val SDATA = 0x0b
    const val STRP = 0x0e
    const val UDATA = 0x0f
    const val REF_ADDR = 0x10
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val INDIRECT = 0x16
    const val SEC_OFFSET = 0x17
    const val EXPLOC = 0x18
    const val FLAG_PRESENT = 0x19
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val REF_SUP4 = 0x1c
    const val STRP_SUP = 0x1d
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOC_LISTX = 0x22
    const val RNGLISTX = 0x23
    const val REF_SUP8 = 0x24
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX1 = 0x29
    const val ADDRX2 = 0x2a
    const val ADDRX3 = 0x2b
    const val ADDRX4 = 0x2c
}

object AbbrevTable {
    /** Parse one abbreviation table starting at [offset] up to its terminating code 0. */
    fun parse(data: ByteArray, offset: Long): Map<Long, Abbrev> {
        if (offset < 0 || offset >= data.size) throw DwarfException("abbrev offset 0x${offset.toString(16)} out of bounds")
        val c = Cursor(data, offset.toInt(), data.size, "debug_abbrev")
        val table = LinkedHashMap<Long, Abbrev>()
        while (!c.exhausted()) {
            val code = c.uleb()
            if (code == 0L) break
            val tag = c.uleb().toInt()
            val hasChildren = c.u8() != 0
            val specs = mutableListOf<AttrSpec>()
            while (true) {
                val name = c.uleb().toInt()
                val form = c.uleb().toInt()
                if (name == 0 && form == 0) break
                val const = if (form == F.IMPLICIT_CONST) c.sleb() else 0L
                specs += AttrSpec(name, form, const)
            }
            table[code] = Abbrev(code, tag, hasChildren, specs)
        }
        return table
    }
}

// ---- Parsed structures -----------------------------------------------------

class DieNode(
    val sectionOffset: Long,
    val tag: Int,
    val depth: Int,
    val attrs: MutableMap<Int, AttrValue>,
    val children: MutableList<DieNode> = mutableListOf(),
    var parent: DieNode? = null
)

data class CompUnit(
    val sectionOffset: Long,
    val version: Int,
    val unitType: Int,
    val is64: Boolean,
    val addrSize: Int,
    val abbrevOffset: Long,
    val root: DieNode?,
    val dies: List<DieNode>,
    val degraded: Boolean,
    val notes: List<String>
)

data class ParsedInfo(val cus: List<CompUnit>, val notes: List<String>)

/** Sections the DIE/attribute decoders may need. */
class DwarfSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val str: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val addr: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rnglists: ByteArray? = null
)

private const val MAX_DIE_DEPTH = 64
private const val MAX_DIE_COUNT = 200_000
private const val MAX_INDIRECT_HOPS = 3

// ---- Attribute decoder -----------------------------------------------------

private class AttrCtx(
    val info: ByteArray,
    val cuStart: Long,
    val is64: Boolean,
    val addrSize: Int,
    val version: Int,
    val sections: DwarfSections,
    val strOffsetsBase: Long,
    val addrBase: Long
)

private fun readStringAt(data: ByteArray, offset: Long): String? {
    if (offset < 0 || offset >= data.size) return null
    var e = offset.toInt()
    while (e < data.size && data[e] != 0.toByte()) e++
    return String(data, offset.toInt(), e - offset.toInt(), Charsets.UTF_8)
}

private fun readAttrValue(c: Cursor, form: Int, specConst: Long, ctx: AttrCtx, hops: Int = 0): AttrValue {
    if (hops > MAX_INDIRECT_HOPS) throw DwarfException("too many DW_FORM_indirect hops in CU@${ctx.cuStart.hex()}")
    when (form) {
        F.ADDR -> return AttrValue.Address(c.addr(ctx.addrSize))
        F.DATA1 -> return AttrValue.Constant(c.u8().toLong())
        F.DATA2 -> return AttrValue.Constant(c.u16().toLong())
        F.DATA16 -> return AttrValue.Block(c.bytes(16))
        F.SDATA -> return AttrValue.Constant(c.sleb())
        F.UDATA, F.REF_UDATA -> {
            val v = c.uleb()
            return if (form == F.UDATA) AttrValue.Constant(v) else cuRelativeRef(v, ctx)
        }
        F.STRING -> return AttrValue.StringVal(c.cstring())
        F.STRP -> {
            val off = c.offset(ctx.is64)
            val s = ctx.sections.str?.let { readStringAt(it, off) }
            if (s == null) return AttrValue.Unknown(F.STRP)
            return AttrValue.StringVal(s)
        }
        F.LINE_STRP -> {
            val off = c.offset(ctx.is64)
            val s = ctx.sections.lineStr?.let { readStringAt(it, off) }
                ?: ctx.sections.str?.let { readStringAt(it, off) }
            if (s == null) return AttrValue.Unknown(F.LINE_STRP)
            return AttrValue.StringVal(s)
        }
        F.REF1 -> return cuRelativeRef(c.u8().toLong(), ctx)
        F.REF2 -> return cuRelativeRef(c.u16().toLong(), ctx)
        F.REF4 -> return cuRelativeRef(c.u32(), ctx)
        F.REF8 -> return cuRelativeRef(c.u64(), ctx)
        F.REF_ADDR -> {
            val off = c.offset(ctx.is64)
            return AttrValue.Reference(off, off < 0 || off >= ctx.info.size)
        }
        F.REF_SIG8 -> return AttrValue.Constant(c.u64())
        F.REF_SUP4 -> return AttrValue.Constant(c.u32())
        F.REF_SUP8 -> return AttrValue.Constant(c.u64())
        F.SEC_OFFSET -> return AttrValue.SecOffset(c.offset(ctx.is64))
        F.EXPLOC -> {
            val len = c.uleb().toInt()
            return AttrValue.Block(c.bytes(len))
        }
        F.BLOCK1 -> return AttrValue.Block(c.bytes(c.u8()))
        F.BLOCK2 -> return AttrValue.Block(c.bytes(c.u16()))
        F.BLOCK4 -> return AttrValue.Block(c.bytes(c.u32().toInt()))
        F.BLOCK -> return AttrValue.Block(c.bytes(c.uleb().toInt()))
        F.FLAG_PRESENT -> return AttrValue.Flag(true)
        F.IMPLICIT_CONST -> return AttrValue.Constant(specConst)
        F.INDIRECT -> {
            val realForm = c.uleb().toInt()
            return readAttrValue(c, realForm, specConst, ctx, hops + 1)
        }
        F.STRX -> return AttrValue.Strx(c.uleb())
        F.STRX1 -> return AttrValue.Strx(c.u8().toLong())
        F.STRX2 -> return AttrValue.Strx(c.u16().toLong())
        F.STRX3 -> return AttrValue.Strx(c.u32())
        F.STRX4 -> return AttrValue.Strx(c.u64())
        F.ADDRX -> return AttrValue.Addrx(c.uleb())
        F.ADDRX1 -> return AttrValue.Addrx(c.u8().toLong())
        F.ADDRX2 -> return AttrValue.Addrx(c.u16().toLong())
        F.ADDRX3 -> return AttrValue.Addrx(c.u32())
        F.ADDRX4 -> return AttrValue.Addrx(c.u64())
        F.LOC_LISTX -> return AttrValue.Loclistx(c.uleb())
        F.RNGLISTX -> return AttrValue.Rnglistx(c.uleb())
        F.STRP_SUP -> { c.offset(ctx.is64); return AttrValue.Unknown(F.STRP_SUP) }
        else -> throw UnknownFormException(form)
    }
}

private fun cuRelativeRef(v: Long, ctx: AttrCtx): AttrValue {
    val target = ctx.cuStart + v
    return AttrValue.Reference(target, target < 0 || target >= ctx.info.size)
}

// ---- .debug_info parser ----------------------------------------------------

object InfoParser {
    fun parse(sections: DwarfSections): ParsedInfo {
        val info = sections.info
        if (info == null) return ParsedInfo(emptyList(), listOf("缺少 .debug_info section，没有可读的 DWARF 单元"))
        if (sections.abbrev == null) return ParsedInfo(emptyList(), listOf("缺少 .debug_abbrev section，无法解析编译单元"))
        val c = Cursor(info, 0, info.size, "debug_info")
        val cus = mutableListOf<CompUnit>()
        val globalNotes = mutableListOf<String>()
        while (!c.exhausted()) {
            val cuOffset = c.pos.toLong()
            if (c.remaining < 4) {
                globalNotes += "CU@${cuOffset.hex()}: 剩余字节不足单元头，已停止解析"
                break
            }
            val lengthStart = c.pos
            var unitLength = c.u32()
            val is64: Boolean
            if (unitLength == 0xffffffffL) {
                is64 = true
                unitLength = c.u64()
            } else is64 = false
            val headerEnd = c.pos.toLong()
            val cuEnd = headerEnd + unitLength
            if (unitLength <= 0 || cuEnd > info.size) {
                globalNotes += "CU@${cuOffset.hex()}: unit_length 越界（声明结束于 ${cuEnd.hex()}，section 长度 ${info.size.hex()}），停止解析"
                break
            }
            val cuCursor = Cursor(info, c.pos, cuEnd.toInt(), "cu@${cuOffset.toString(16)}")
            c.pos = cuEnd.toInt()

            val notes = mutableListOf<String>()
            var degraded = false
            val version: Int
            var unitType = UnitType.COMPILE
            var addrSize = 8
            var abbrevOffset = 0L
            try {
                version = cuCursor.u16()
                if (version < 2 || version > 5) throw DwarfException("CU@${cuOffset.hex()}: 不支持的 DWARF 版本 $version")
                if (version >= 5) {
                    unitType = cuCursor.u8()
                    addrSize = cuCursor.u8()
                    abbrevOffset = cuCursor.offset(is64)
                } else {
                    abbrevOffset = cuCursor.offset(is64)
                    addrSize = cuCursor.u8()
                }
                if (addrSize != 4 && addrSize != 8) throw DwarfException("CU@${cuOffset.hex()}: 非法地址宽度 $addrSize")
            } catch (e: DwarfException) {
                notes += e.message!!
                cus += CompUnit(cuOffset, 0, unitType, is64, addrSize, abbrevOffset, null, emptyList(), true, notes)
                continue
            }

            val abbrevs = try {
                AbbrevTable.parse(sections.abbrev, abbrevOffset)
            } catch (e: DwarfException) {
                notes += "abbrev 表 @${abbrevOffset.hex()} 无法解析: ${e.message}"
                cus += CompUnit(cuOffset, version, unitType, is64, addrSize, abbrevOffset, null, emptyList(), true, notes)
                continue
            }

            val (root, dies) = try {
                parseDies(cuCursor, cuOffset, is64, version, addrSize, abbrevs, sections, notes)
            } catch (e: UnknownFormException) {
                notes += "遇到未实现/未知 form 0x${e.formCode.toString(16)}（CU@${cuCursor.pos.toString(16)}），该 CU 在此处隔离中止；游标被 CU 长度约束，不会影响后续单元"
                degraded = true
                null to emptyList()
            } catch (e: DwarfException) {
                notes += "DIE 解析中止于 0x${cuCursor.pos.toString(16)}: ${e.message}（已解析部分保留）"
                degraded = true
                null to emptyList()
            }

            // CU-level structural notes
            root?.attrs?.let { attrs ->
                if (unitType == UnitType.SKELETON || attrs.containsKey(At.GNU_DWO_NAME) || attrs.containsKey(At.DWO_NAME)) {
                    val dwo = (attrs[At.GNU_DWO_NAME] as? AttrValue.StringVal)?.v
                        ?: (attrs[At.DWO_NAME] as? AttrValue.StringVal)?.v
                    notes += "split DWARF: 骨架单元引用 ${dwo ?: "<未命名 dwo>"}，当前未导入对应 .dwo；" +
                        "骨架内的地址范围与归属仍可信，但完整的行号/变量/内联树位于 dwo 中，可能不完整"
                    degraded = true
                }
                if (root.tag == Tag.COMPILE_UNIT && root.attrs[At.STMT_LIST] == null &&
                    unitType != UnitType.SKELETON
                ) {
                    // not fatal, just noting
                }
            }
            if (usesAddrx(root) && sections.addr == null) {
                notes += "DIE 使用 addrx 索引但缺少 .debug_addr section：依赖地址索引的范围无法解析"
                degraded = true
            }
            if (usesStrx(root) && sections.strOffsets == null && sections.str == null) {
                notes += "DIE 使用 strx 索引但缺少 .debug_str_offsets/.debug_str：名称可能缺失（不影响地址归属）"
                degraded = true
            }

            cus += CompUnit(cuOffset, version, unitType, is64, addrSize, abbrevOffset, root, dies, degraded, notes)
        }
        return ParsedInfo(cus, globalNotes)
    }

    private fun usesAddrx(root: DieNode?): Boolean =
        root != null && root.attrs.values.any { it is AttrValue.Addrx || it is AttrValue.Rnglistx }
    private fun usesStrx(root: DieNode?): Boolean =
        root != null && root.attrs.values.any { it is AttrValue.Strx }

    private fun parseDies(
        c: Cursor,
        cuStart: Long,
        is64: Boolean,
        version: Int,
        addrSize: Int,
        abbrevs: Map<Long, Abbrev>,
        sections: DwarfSections,
        notes: MutableList<String>
    ): Pair<DieNode, List<DieNode>> {
        val all = mutableListOf<DieNode>()
        var count = 0
        var strOffsetsBase = 0L
        var addrBase = 0L

        fun makeCtx(): AttrCtx {
            // base attributes are filled as the root is read; for non-root DIEs use the captured values.
            return AttrCtx(c.data, cuStart, is64, addrSize, version, sections, strOffsetsBase, addrBase)
        }

        fun readDie(depth: Int, parent: DieNode?): DieNode? {
            val dieOffset = c.pos.toLong()
            val code = c.uleb()
            if (code == 0L) return null
            val ab = abbrevs[code]
                ?: throw DwarfException("未知 abbrev code $code @0x${dieOffset.toString(16)}")
            val node = DieNode(dieOffset, ab.tag, depth, mutableMapOf())
            node.parent = parent
            all += node
            if (++count > MAX_DIE_COUNT) throw DwarfException("CU 内 DIE 数量超过上限 $MAX_DIE_COUNT")
            for (spec in ab.attrs) {
                val v = readAttrValue(c, spec.form, spec.implicitConst, makeCtx())
                node.attrs[spec.name] = v
                when (spec.name) {
                    At.STR_OFFSETS_BASE -> strOffsetsBase = (v as? AttrValue.SecOffset)?.v ?: 0L
                    At.ADDR_BASE -> addrBase = (v as? AttrValue.SecOffset)?.v ?: 0L
                }
                if (v is AttrValue.Reference && v.outOfBounds) {
                    notes += "DIE@${dieOffset.hex()} 的 ${attrName(spec.name)} 引用 ${v.v.hex()} 越出 .debug_info（长度 ${c.data.size.hex()}），该引用将解析为空"
                }
            }
            if (ab.hasChildren) {
                if (depth + 1 > MAX_DIE_DEPTH) throw DwarfException("DIE 嵌套深度超过上限 $MAX_DIE_DEPTH @${dieOffset.hex()}")
                while (true) {
                    if (c.exhausted()) throw DwarfException("子 DIE 列表未在 CU 边界前结束（缺少 null DIE）")
                    val child = readDie(depth + 1, node) ?: break
                    node.children += child
                }
            }
            return node
        }

        if (c.exhausted()) throw DwarfException("CU 无任何 DIE")
        val root = readDie(0, null) ?: throw DwarfException("CU 根 DIE 缺失")
        return root to all
    }
}

fun attrName(code: Int): String = "DW_AT_0x${code.toString(16)}"
