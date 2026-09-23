package compass.query

import compass.dwarf.*
import compass.elf.ElfFile
import java.security.MessageDigest

data class ImportResult(
    val fileId: Long,
    val name: String,
    val sha256: String,
    val sections: Int,
    val cus: Int,
    val sequences: Int,
    val lineRows: Int,
    val scopes: Int,
    val notes: List<String>,
)

/** Imports an ELF file: parses DWARF, extracts scopes/line programs, persists everything. */
class Importer(private val store: Store) {

    fun import(fileName: String, bytes: ByteArray): ImportResult {
        val notes = ArrayList<String>()
        val elf = ElfFile(bytes)
        notes.addAll(elf.warnings)
        val sha = elf.rawByteDigest()

        val sectionNames = listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str", ".debug_line_str",
            ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists",
        )
        val sectionMap = HashMap<String, ByteArray>()
        for (n in sectionNames) elf.section(n)?.let { sectionMap[n] = it }
        val sections = DebugSections(sectionMap, elf.littleEndian)

        val cus: List<CompilationUnit> = try {
            DebugInfoParser(sections, notes).parse()
        } catch (e: Exception) {
            notes.add("debug info parse failed: ${e.message}")
            emptyList()
        }

        var lineRowCount = 0
        var sequenceCount = 0
        var scopeCount = 0

        val fileId = store.tx {
            val fid = store.insert(
                "INSERT INTO debug_file(name, sha256, size, notes) VALUES(?,?,?,?)",
                fileName, sha, bytes.size.toLong(), ""
            )
            for (s in elf.sections) {
                if (s.name.isEmpty()) continue
                val digest = elf.section(s.name)?.let { sha256(it) } ?: ""
                store.insert(
                    "INSERT INTO section(file_id,name,type,flags,addr,offset,size,sha256) VALUES(?,?,?,?,?,?,?,?)",
                    fid, s.name, s.type.toLong(), s.flags, s.addr, s.offset, s.size, digest
                )
            }
            for (cu in cus) {
                val cuId = store.insert(
                    """INSERT INTO cu(file_id,cu_index,offset,version,unit_type,address_size,name,comp_dir,producer,dwo_name,low_pc,stmt_list,degraded,notes)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    fid, cu.index.toLong(), cu.offset, cu.version.toLong(), cu.unitType.toLong(), cu.addressSize.toLong(),
                    cu.name, cu.compDir, cu.producer, cu.dwoName, cu.lowPc, cu.stmtList,
                    if (cu.degraded) 1L else 0L, cu.notes.joinToString("\n")
                )
                // Line program.
                val stmt = cu.stmtList
                if (stmt != null) {
                    val resolver = CuAttributeResolver(sections, cu)
                    val lp = LineProgramParser(sections, cu, resolver).parse(stmt)
                    if (lp != null) {
                        cu.lineProgram = lp
                        for (seq in lp.sequences) {
                            if (seq.rows.isEmpty()) continue
                            val seqId = store.insert(
                                "INSERT INTO line_sequence(file_id,cu_id,seq_index,start,end) VALUES(?,?,?,?,?)",
                                fid, cuId, seq.index.toLong(), seq.start, seq.end
                            )
                            sequenceCount++
                            for (row in seq.rows) {
                                store.insert(
                                    """INSERT INTO line_row(sequence_id,address,file,line,col,is_stmt,end_seq,basic_block,prologue_end,epilogue_begin,discriminator)
                                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                                    seqId, row.address, lp.fileName(row.file), row.line, row.column,
                                    if (row.isStmt) 1L else 0L, if (row.endSequence) 1L else 0L,
                                    if (row.basicBlock) 1L else 0L, if (row.prologueEnd) 1L else 0L,
                                    if (row.epilogueBegin) 1L else 0L, row.discriminator
                                )
                                lineRowCount++
                            }
                        }
                        if (lp.notes.isNotEmpty()) {
                            val merged = (cu.notes + lp.notes).joinToString("\n")
                            store.exec("UPDATE cu SET notes=? WHERE id=?", merged, cuId)
                        }
                    }
                }
                // Scopes.
                scopeCount += extractScopes(store, sections, cu, fid, cuId)
            }
            fid
        }
        return ImportResult(fileId, fileName, sha, elf.sections.count { it.name.isNotEmpty() }, cus.size, sequenceCount, lineRowCount, scopeCount, notes)
    }

    private fun extractScopes(store: Store, sections: DebugSections, cu: CompilationUnit, fileId: Long, cuId: Long): Int {
        val root = cu.root ?: return 0
        val resolver = CuAttributeResolver(sections, cu)
        resolver.resolve() // idempotent re-resolve for name lookup tables
        val rangeParser = RangeListParser(sections, cu)
        var count = 0

        fun rangesOf(die: Die): List<AddressRange> {
            val low = resolver.addrAttr(die, Attr.LOW_PC)
            val highAttr = die.attr(Attr.HIGH_PC)
            if (low != null && highAttr != null) {
                val high = when (highAttr) {
                    // DWARF: high_pc may be an absolute address or a constant offset from low_pc.
                    is AttrValue.Addr -> highAttr.v
                    is AttrValue.UInt -> low + highAttr.v
                    is AttrValue.SInt -> low + highAttr.v
                    else -> null
                }
                if (high != null) return listOf(AddressRange(low, high))
            }
            val rangesAttr = die.attr(Attr.RANGES)
            if (rangesAttr != null) return rangeParser.parse(rangesAttr)
            if (low != null) return listOf(AddressRange(low, low)) // zero-length, kept for display
            return emptyList()
        }

        fun isScopeTag(tag: Int): Boolean = tag == Tag.SUBPROGRAM || tag == Tag.INLINED_SUBROUTINE ||
            tag == Tag.LEXICAL_BLOCK || tag == Tag.LABEL || tag == Tag.TRY_BLOCK || tag == Tag.CATCH_BLOCK

        fun walk(die: Die, parentScopeId: Long?) {
            var myId = parentScopeId
            if (isScopeTag(die.tag)) {
                val ranges = rangesOf(die)
                val name = resolver.resolveName(die)
                val callFileIdx = resolver.uintAttr(die, Attr.CALL_FILE)?.toInt()
                val callLine = resolver.uintAttr(die, Attr.CALL_LINE)
                val callColumn = resolver.uintAttr(die, Attr.CALL_COLUMN)
                val callFileName = callFileIdx?.let { cu.lineProgram?.fileName(it) }
                if (ranges.isNotEmpty() || die.tag == Tag.INLINED_SUBROUTINE || die.tag == Tag.SUBPROGRAM) {
                    myId = store.insert(
                        """INSERT INTO scope(file_id,cu_id,die_offset,tag,name,depth,parent_id,call_file,call_line,call_column)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        fileId, cuId, die.offset, die.tag.toLong(), name, die.depth.toLong(), parentScopeId,
                        callFileName, callLine, callColumn
                    )
                    for (r in ranges) {
                        store.insert("INSERT INTO scope_range(scope_id,start,end) VALUES(?,?,?)", myId, r.start, r.end)
                    }
                    count++
                }
            }
            for (c in die.children) walk(c, myId)
        }
        walk(root, null)
        return count
    }

    companion object {
        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
