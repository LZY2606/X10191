package compass.db

import compass.dwarf.DW_AT
import compass.dwarf.DwarfImage
import compass.dwarf.DwarfParser
import compass.dwarf.tableVersionSummary
import compass.dwarf.DW_TAG
import compass.elf.ElfParser
import java.security.MessageDigest

/** One stored import row plus the lazily re-parsed in-memory image. */
class StoredVersion(
    private val id: Long,
    private val versionLabel: String,
    private val versionPriority: Int,
    val tableVersion: String,
    private val dwarfImage: DwarfImage
) : compass.dwarf.DebugVersion {
    override val versionId get() = id
    override val label get() = versionLabel
    override val priority get() = versionPriority
    override val image get() = dwarfImage
}

data class VersionMeta(
    val id: Long, val label: String, val priority: Int, val sha256: String,
    val buildId: String?, val sizeBytes: Long, val tableVersion: String,
    val hasSplit: Boolean, val importedAt: Long
)

class VersionRepository(private val db: Database) {

    fun import(
        label: String, bytes: ByteArray, priority: Int = 100,
        fileName: String? = null, splitBytes: ByteArray? = null
    ): StoredVersion {
        val image = DwarfParser.parseBytes(bytes, fileName, splitBytes)
        val sha = sha256(bytes)
        val splitSha = splitBytes?.let { sha256(it) }
        val buildId = image.elf.buildId()
        val now = System.currentTimeMillis()
        db.conn.prepareStatement("""
            INSERT INTO debug_version(label,file_name,sha256,build_id,size_bytes,elf_class,little_endian,
              machine,priority,imported_at,table_version,has_split,split_sha256)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            ps.setString(1, label); ps.setString(2, fileName); ps.setString(3, sha)
            ps.setString(4, buildId); ps.setLong(5, bytes.size.toLong())
            ps.setInt(6, image.elf.elfClass); ps.setInt(7, if (image.elf.littleEndian) 1 else 0)
            ps.setInt(8, image.elf.machine); ps.setInt(9, priority); ps.setLong(10, now)
            ps.setString(11, image.tableVersionSummary())
            ps.setInt(12, if (splitBytes != null) 1 else 0); ps.setString(13, splitSha)
            ps.executeUpdate()
        }
        val id = db.conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
        storeSections(id, image)
        storeCusAndDies(id, image)
        storeSequences(id, image)
        storeDiagnostics(id, image)
        return StoredVersion(id, label, priority, image.tableVersionSummary(), image)
    }

    private fun storeSections(id: Long, image: DwarfImage) {
        db.conn.prepareStatement("""
            INSERT INTO raw_section(version_id,name,addr,offset,size,sha256,bytes)
            VALUES(?,?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            // Full executable blob keeps the version re-parseable even if section mapping changes.
            ps.setLong(1, id); ps.setString(2, "__elf_full__")
            ps.setLong(3, 0); ps.setLong(4, 0); ps.setLong(5, image.elf.raw.size.toLong())
            ps.setString(6, sha256(image.elf.raw)); ps.setBytes(7, image.elf.raw)
            ps.executeUpdate()
            image.splitElf?.let { sp ->
                ps.setLong(1, id); ps.setString(2, "__dwo_full__")
                ps.setLong(3, 0); ps.setLong(4, 0); ps.setLong(5, sp.raw.size.toLong())
                ps.setString(6, sha256(sp.raw)); ps.setBytes(7, sp.raw)
                ps.executeUpdate()
            }
            val all = image.elf.sections.filter { it.name.isNotEmpty() }
            for (sec in all) {
                val raw = try {
                    image.elf.sectionBytes(sec.name)
                } catch (e: Exception) { null } ?: continue
                ps.setLong(1, id); ps.setString(2, sec.name)
                ps.setLong(3, sec.addr); ps.setLong(4, sec.offset); ps.setLong(5, sec.size)
                ps.setString(6, sha256(raw)); ps.setBytes(7, raw)
                ps.executeUpdate()
            }
        }
    }

    private fun storeCusAndDies(id: Long, image: DwarfImage) {
        val allCus = image.cus + image.splitCus
        db.conn.prepareStatement("""
            INSERT INTO comp_unit(version_id,cu_offset,dwarf_version,unit_type,address_size,
              name,comp_dir,is_skeleton,is_dwo,dwo_id,dwo_name,dwo_resolved)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            for (cu in allCus) {
                val root = cu.root
                ps.setLong(1, id); ps.setLong(2, cu.offset); ps.setInt(3, cu.version)
                ps.setInt(4, cu.unitType); ps.setInt(5, cu.addressSize)
                ps.setString(6, root?.str(DW_AT.NAME))
                ps.setString(7, root?.str(DW_AT.COMP_DIR))
                ps.setInt(8, if (cu.isSkeleton) 1 else 0)
                ps.setInt(9, if (cu.isDwo) 1 else 0)
                ps.setString(10, cu.dwoId?.toString(16))
                ps.setString(11, cu.dwoName)
                ps.setInt(12, if (cu.dwoResolved) 1 else 0)
                ps.executeUpdate()
            }
        }
        db.conn.prepareStatement("""
            INSERT INTO die_node(version_id,cu_offset,die_offset,tag,depth,parent_offset,
              name,linkage_name,low_pc,high_pc,decl_file,decl_line,is_inline)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            for (cu in allCus) {
                cu.root?.let { root -> walk(root) { d -> insertDie(ps, id, cu, d) } }
            }
        }
        db.conn.prepareStatement("""
            INSERT INTO address_range(version_id,die_offset,start,end,zero_length,source)
            VALUES(?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            for (cu in allCus) cu.root?.let { root ->
                walk(root) { d ->
                    for (rg in d.ranges) {
                        ps.setLong(1, id); ps.setLong(2, d.offset)
                        ps.setLong(3, rg.start); ps.setLong(4, rg.end)
                        ps.setInt(5, if (rg.zeroLength) 1 else 0); ps.setString(6, rg.source.name)
                        ps.executeUpdate()
                    }
                }
            }
        }
    }

    private fun insertDie(ps: java.sql.PreparedStatement, id: Long, cu: compass.dwarf.CompUnit, d: compass.dwarf.DieNode) {
        val low = (d.attr(DW_AT.LOW_PC)?.value as? compass.dwarf.AttrValue.Addr)?.v
        val high = when (val h = d.attr(DW_AT.HIGH_PC)?.value) {
            is compass.dwarf.AttrValue.Addr -> "0x${h.v.toString(16)}"
            is compass.dwarf.AttrValue.Number -> "+${h.v}"
            else -> null
        }
        ps.setLong(1, id); ps.setLong(2, cu.offset); ps.setLong(3, d.offset)
        ps.setInt(4, d.tag); ps.setInt(5, d.depth)
        ps.setObject(6, d.parent?.offset)
        ps.setString(7, d.str(DW_AT.NAME)); ps.setString(8, d.str(DW_AT.LINKAGE_NAME))
        ps.setString(9, low?.let { "0x${it.toString(16)}" })
        ps.setString(10, high)
        ps.setString(11, null)
        ps.setObject(12, d.num(DW_AT.DECL_LINE)?.toInt())
        ps.setInt(13, if (d.tag == DW_TAG.INLINED_SUBROUTINE) 1 else 0)
        ps.executeUpdate()
    }

    private fun storeSequences(id: Long, image: DwarfImage) {
        db.conn.prepareStatement("""
            INSERT INTO line_sequence(version_id,seq_local_id,cu_offset,start_address,end_address,
              dwarf_version,segmented) VALUES(?,?,?,?,?,?,?)
        """.trimIndent()).use { seqPs ->
            db.conn.prepareStatement("""
                INSERT INTO line_row(seq_pk,address,file_id,file_name,line,column,is_stmt,
                  end_sequence,prologue_end,discriminator) VALUES(?,?,?,?,?,?,?,?,?,?)
            """.trimIndent()).use { rowPs ->
                db.conn.prepareStatement("""
                    INSERT INTO line_event(seq_pk,seq_pos,address,file,line,column,is_stmt,kind,detail)
                    VALUES(?,?,?,?,?,?,?,?,?)
                """.trimIndent()).use { evPs ->
                    for (seq in image.sequences) {
                        seqPs.setLong(1, id); seqPs.setInt(2, seq.id); seqPs.setLong(3, seq.cuOffset)
                        seqPs.setLong(4, seq.startAddress); seqPs.setLong(5, seq.endAddress)
                        seqPs.setInt(6, seq.dwarfVersion); seqPs.setInt(7, if (seq.segmented) 1 else 0)
                        seqPs.executeUpdate()
                        val seqPk = db.conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
                        for (row in seq.rows) {
                            rowPs.setLong(1, seqPk); rowPs.setLong(2, row.address)
                            rowPs.setInt(3, row.fileId); rowPs.setString(4, seq.fileOf(row.fileId))
                            rowPs.setInt(5, row.line); rowPs.setInt(6, row.column)
                            rowPs.setInt(7, if (row.isStmt) 1 else 0)
                            rowPs.setInt(8, if (row.endSequence) 1 else 0)
                            rowPs.setInt(9, if (row.prologueEnd) 1 else 0)
                            rowPs.setInt(10, row.discriminator)
                            rowPs.executeUpdate()
                        }
                        for (ev in seq.events) {
                            evPs.setLong(1, seqPk); evPs.setInt(2, ev.seqPos)
                            evPs.setLong(3, ev.address); evPs.setString(4, ev.file)
                            evPs.setInt(5, ev.line); evPs.setInt(6, ev.column)
                            evPs.setInt(7, if (ev.isStmt) 1 else 0)
                            evPs.setString(8, ev.kind); evPs.setString(9, ev.opcodeDetail)
                            evPs.executeUpdate()
                        }
                    }
                }
            }
        }
    }

    private fun storeDiagnostics(id: Long, image: DwarfImage) {
        db.conn.prepareStatement("""
            INSERT INTO parse_diagnostic(version_id,severity,code,message,section,offset)
            VALUES(?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            for (d in image.diagnostics) {
                ps.setLong(1, id); ps.setString(2, d.severity); ps.setString(3, d.code)
                ps.setString(4, d.message); ps.setString(5, d.section)
                ps.setObject(6, d.offset); ps.executeUpdate()
            }
        }
    }

    fun listMeta(): List<VersionMeta> = db.conn.createStatement().executeQuery("""
        SELECT id,label,priority,sha256,build_id,size_bytes,table_version,has_split,imported_at
        FROM debug_version ORDER BY id
    """).use { rs ->
        val out = mutableListOf<VersionMeta>()
        while (rs.next()) out.add(VersionMeta(
            rs.getLong(1), rs.getString(2), rs.getInt(3), rs.getString(4),
            rs.getString(5), rs.getLong(6), rs.getString(7), rs.getInt(8) == 1, rs.getLong(9)))
        out
    }

    /** Rebuild the executable ELF from stored raw section bytes and re-parse (immutable). */
    fun load(id: Long): StoredVersion? {
        val meta = db.conn.prepareStatement(
            "SELECT label,priority FROM debug_version WHERE id=?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs ->
                if (!rs.next()) return null else rs.getString(1) to rs.getInt(2)
            }
        }
        val rows = db.conn.prepareStatement(
            "SELECT name,bytes FROM raw_section WHERE version_id=? ORDER BY id").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs ->
                val out = mutableListOf<Pair<String, ByteArray>>()
                while (rs.next()) out.add(rs.getString(1) to rs.getBytes(2))
                out
            }
        }
        // Reconstruct an ELF by reusing original section bytes; simplest faithful route is to
        // keep the complete executable blob stored as a synthetic ".elf" section on import.
        val full = rows.firstOrNull { it.first == "__elf_full__" }?.second
            ?: error("版本 $id 的原始 ELF 字节缺失")
        val split = rows.firstOrNull { it.first == "__dwo_full__" }?.second
        val image = DwarfParser.parseBytes(full, null, split)
        return StoredVersion(id, meta.first, meta.second, image.tableVersionSummary(), image)
    }

    fun loadAll(): List<StoredVersion> = listMeta().mapNotNull { load(it.id) }

    private fun walk(d: compass.dwarf.DieNode, fn: (compass.dwarf.DieNode) -> Unit) {
        fn(d); d.children.forEach { walk(it, fn) }
    }

    private fun sha256(b: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
