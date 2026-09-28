package com.linecompass.dwarf

import com.linecompass.io.ByteReader
import com.linecompass.io.ParseException

/**
 * Parses .debug_info into CompilationUnits with DIE trees.
 * Corruption in one CU is isolated: reported in [ParsedDebugFile.issues], and
 * parsing continues with the next CU. An unknown form aborts only that CU so
 * the cursor can never drift onto later DIEs.
 */
class InfoParser(
    private val info: ByteArray,
    private val abbrevBytes: ByteArray?,
    private val strings: StringTables,
    private val addrs: AddrTableReader,
    private val issues: MutableList<ParseIssue>
) {
    val units = mutableListOf<CompilationUnit>()
    private val abbrevCache = HashMap<Long, AbbrevTable?>()

    fun parse() {
        var guard = 0
        var pos = 0
        while (pos < info.size) {
            if (++guard > Limits.MAX_CUS) {
                issues += ParseIssue(".debug_info", "ERROR", "TOO_MANY_CUS",
                    "exceeded ${Limits.MAX_CUS} CUs, stopping scan at 0x${pos.toString(16)}")
                return
            }
            val unitStart = pos
            val il = try {
                readInitialLength(unitStart)
            } catch (e: Exception) {
                issues += ParseIssue(".debug_info", "ERROR", "CU_LENGTH_OOB",
                    "cannot read unit length at 0x${unitStart.toString(16)}: ${e.message}")
                return
            }
            val unitEnd = il.contentStart + il.length.toInt()
            if (unitEnd > info.size) {
                issues += ParseIssue(".debug_info", "ERROR", "CU_TRUNCATED",
                    "CU at 0x${unitStart.toString(16)} claims end 0x${unitEnd.toString(16)} beyond section ${info.size}")
                return
            }
            parseOne(unitStart, il, unitEnd)
            pos = unitEnd
        }
    }

    private data class InitialLength(val is64: Boolean, val length: Long, val contentStart: Int, val le: Boolean)

    private fun readInitialLength(start: Int): InitialLength {
        val r = ByteReader(info, true, ".debug_info", start)
        val first = r.u4()
        if (first != 0xffffffffL && first < 0xfffffff0L) return InitialLength(false, first, start + 4, true)
        if (first == 0xffffffffL) return InitialLength(true, r.u8(), start + 12, true)
        val rb = ByteReader(info, false, ".debug_info", start)
        val fb = rb.u4()
        if (fb != 0xffffffffL && fb < 0xfffffff0L) return InitialLength(false, fb, start + 4, false)
        if (fb == 0xffffffffL) return InitialLength(true, rb.u8(), start + 12, false)
        throw ParseException("reserved initial length at 0x$start")
    }

    private fun parseOne(unitStart: Int, il: InitialLength, unitEnd: Int) {
        val r = ByteReader(info, il.le, ".debug_info", il.contentStart)
        val version = try { r.u2() } catch (e: Exception) {
            issues += ParseIssue(".debug_info", "ERROR", "CU_VERSION_OOB",
                "cannot read version at 0x${unitStart.toString(16)}", cuOffset = unitStart.toLong()); return
        }
        val offsetSize = if (il.is64) 8 else 4
        var unitType = DW.UT_compile
        var addressSize = 8
        var abbrevOffset: Long

        try {
            if (version >= 5) {
                unitType = r.u1()
                addressSize = r.u1()
                abbrevOffset = r.u(offsetSize)
                if (unitType == DW.UT_type || unitType == DW.UT_split_type) {
                    r.u8() // type signature
                    r.u(offsetSize) // type offset
                }
            } else {
                abbrevOffset = r.u(offsetSize)
                addressSize = r.u1()
            }
        } catch (e: Exception) {
            issues += ParseIssue(".debug_info", "ERROR", "CU_HEADER_OOB",
                "truncated CU header at 0x${unitStart.toString(16)}: ${e.message}",
                cuOffset = unitStart.toLong()); return
        }

        val kind = when (unitType) {
            DW.UT_compile -> CuKind.COMPILE
            DW.UT_skeleton -> CuKind.SKELETON
            DW.UT_split_compile -> CuKind.SPLIT_COMPILE
            DW.UT_type, DW.UT_split_type -> CuKind.TYPE
            DW.UT_partial -> CuKind.PARTIAL
            else -> CuKind.OTHER
        }

        val cu = CompilationUnit(
            offset = unitStart.toLong(), length = il.length, version = version,
            is64BitDwarf = il.is64, unitType = unitType, kind = kind,
            addressSize = addressSize, abbrevOffset = abbrevOffset, dwoId = null,
            root = null, dieByOffset = emptyMap(), lineProgram = null,
            ranges = emptyList(), littleEndian = il.le
        )

        val table = if (abbrevBytes == null) null else abbrevCache.getOrPut(abbrevOffset) {
            AbbrevParser.parseTable(abbrevBytes, abbrevOffset, il.le, issues)
        }
        if (table == null) {
            issues += ParseIssue(".debug_info", "ERROR", "NO_ABBREV_TABLE",
                "CU 0x${unitStart.toString(16)} cannot decode without .debug_abbrev",
                cuOffset = unitStart.toLong())
            units += cu
            return
        }

        val dieMap = HashMap<Long, DieNode>()
        val cuDataStart = r.offset
        val ctx = CuDecodeCtx(CuDecodeCtx.CompilationUnitRef(cu), offsetSize, il.le, strings, addrs, issues)
        try {
            val rootNode = parseDieTree(r, table, cu, null, dieMap, ctx,
                unitStart.toLong(), cuDataStart, unitEnd, depth = 1)
                ?: throw ParseException("CU has no root DIE")
            assignCu(rootNode, cu)
            cu.root = rootNode
            cu.dieByOffset = dieMap
            extractRootAttrs(cu, rootNode)
            units += cu
        } catch (e: UnknownFormException) {
            issues += ParseIssue(".debug_info", "ERROR", "UNKNOWN_FORM",
                "CU 0x${unitStart.toString(16)} aborted: ${e.message}; " +
                    "remaining DIEs of this CU are skipped to avoid cursor drift",
                offset = e.offset.toLong(), cuOffset = unitStart.toLong())
            units += cu
        } catch (e: Exception) {
            issues += ParseIssue(".debug_info", "ERROR", "DIE_PARSE_FAILED",
                "CU 0x${unitStart.toString(16)} aborted at 0x${r.offset.toString(16)}: ${e.message}",
                offset = r.offset.toLong(), cuOffset = unitStart.toLong())
            units += cu
        }
    }

    private fun assignCu(node: DieNode, cu: CompilationUnit) {
        node.cu = cu
        node.children.forEach { assignCu(it, cu) }
    }

    private fun extractRootAttrs(cu: CompilationUnit, root: DieNode) {
        cu.strOffsetsBase = root.num(DW.AT_str_offsets_base)
            ?: root.num(DW.AT_GNU_str_offsets_base) ?: 0L
        cu.addrBase = root.num(DW.AT_addr_base) ?: root.num(DW.AT_GNU_addr_base) ?: 0L
    }

    private fun parseDieTree(
        r: ByteReader,
        table: AbbrevTable,
        cu: CompilationUnit,
        parent: DieNode?,
        dieMap: MutableMap<Long, DieNode>,
        ctx: CuDecodeCtx,
        cuGlobalOffset: Long,
        cuDataStart: Int,
        dieEnd: Int,
        depth: Int
    ): DieNode? {
        if (depth > Limits.MAX_RECURSION) throw ParseException("DIE nesting exceeds ${Limits.MAX_RECURSION}")
        if (dieMap.size >= Limits.MAX_DIES) throw ParseException("DIE safety limit reached")
        val offset = cuGlobalOffset + (r.offset - cuDataStart)
        val code = r.uleb128()
        if (code == 0L) return null
        val decl = table.lookup(code)
            ?: throw ParseException("abbrev code $code not in table at 0x${r.offset.toString(16)}")
        val attrs = decl.attrs.map { aa ->
            Attr(aa.name, aa.form,
                FormReader.read(r, aa.form, aa.implicitConst, ctx, cuDataStart, cuGlobalOffset))
        }
        val node = DieNode(offset = offset, tag = decl.tag, attributes = attrs,
            children = emptyList(), cu = cu, parent = parent)
        dieMap[offset] = node
        val kids = mutableListOf<DieNode>()
        if (decl.hasChildren) {
            while (true) {
                if (r.offset >= dieEnd) throw ParseException("DIE tree unterminated at CU end 0x${dieEnd.toString(16)}")
                val child = parseDieTree(r, table, cu, node, dieMap, ctx,
                    cuGlobalOffset, cuDataStart, dieEnd, depth + 1) ?: break
                kids += child
            }
        }
        return node.copy(children = kids)
    }
}
