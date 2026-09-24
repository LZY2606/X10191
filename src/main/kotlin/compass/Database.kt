package compass

import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager

data class VersionRecord(val id: Long, val fileName: String, val elfClass: Int, val endian: Int, val machine: Int, val sha256: String, val importedAt: String, val cuCount: Int, val sectionCount: Int)
data class SnapshotRecord(val id: Long, val label: String, val versionId: Long, val moduleBase: Long, val relativeBase: Long, val loadBias: Long, val segment: Int?, val createdAt: String)

class CompassDatabase(path: Path) {
    val connection: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    init {
        connection.createStatement().executeUpdate("PRAGMA foreign_keys=ON")
        migrate()
    }

    private fun migrate() {
        connection.createStatement().executeUpdate("""
            create table if not exists versions (
              id integer primary key autoincrement, file_name text not null, elf_class integer not null,
              endian integer not null, machine integer not null, sha256 text not null, imported_at text not null,
              cu_count integer not null, section_count integer not null
            )""")
        connection.createStatement().executeUpdate("""
            create table if not exists warnings (id integer primary key autoincrement, version_id integer not null references versions(id), stage text not null, severity text not null, offset text, message text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists sections (
              id integer primary key autoincrement, version_id integer not null references versions(id), ordinal integer not null,
              name text not null, type text not null, flags text not null, address text not null, section_offset text not null,
              size text not null, link integer not null, info integer not null, alignment text not null, entry_size text not null, sha256 text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists cus (
              id integer primary key autoincrement, version_id integer not null references versions(id), ordinal integer not null,
              dwarf_offset text not null, size text not null, version_no integer not null, unit_type integer not null,
              address_size integer not null, segment_size integer not null, abbrev_offset text not null, line_offset text,
              low_pc text, name text, comp_dir text, dwo_name text, dwo_id text, split_status text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists dies (
              id integer primary key autoincrement, cu_id integer not null references cus(id), ordinal integer not null,
              dwarf_offset text not null, tag integer not null, tag_name text not null, depth integer not null,
              parent_offset text, name text, linkage_name text, low_pc text, high_pc text, ranges_offset text,
              call_file integer, call_line integer, inline_value integer, abstract_origin text, specification text)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists die_ranges (
              id integer primary key autoincrement, die_id integer not null references dies(id), start_address text not null,
              end_address text not null, segment integer not null, source text not null, range_ordinal integer not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists source_files (
              id integer primary key autoincrement, cu_id integer not null references cus(id), ordinal integer not null,
              name text not null, directory text not null, path text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists line_sequences (
              id integer primary key autoincrement, cu_id integer not null references cus(id), ordinal integer not null,
              start_address text not null, end_address text not null, segment integer not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists line_rows (
              id integer primary key autoincrement, sequence_id integer not null references line_sequences(id),
              ordinal integer not null, address text not null, segment integer not null, file_ordinal integer,
              file_name text, line_no integer not null, column_no integer not null, isa integer not null,
              discriminator integer not null, is_stmt integer not null, basic_block integer not null,
              prologue_end integer not null, epilogue_begin integer not null, end_sequence integer not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists snapshots (
              id integer primary key autoincrement, label text not null, version_id integer not null references versions(id),
              module_base text not null, relative_base text not null, load_bias text not null, segment integer, created_at text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists batches (
              id integer primary key autoincrement, snapshot_id integer not null references snapshots(id),
              raw_text text not null, created_at text not null)
        """)
        connection.createStatement().executeUpdate("""
            create table if not exists frames (
              id integer primary key autoincrement, batch_id integer not null references batches(id), ordinal integer not null,
              input_address text not null, relative_address text not null, result_json text not null)
        """)
    }

    fun saveParsed(fileName: String, parsed: ParsedFile): Long {
        val now = java.time.Instant.now().toString()
        val versionId = connection.prepareStatement("""insert into versions(file_name, elf_class, endian, machine, sha256, imported_at, cu_count, section_count) values(?,?,?,?,?,?,?,?)""", java.sql.Statement.RETURN_GENERATED_KEYS).use { stmt ->
            stmt.setString(1, fileName); stmt.setInt(2, parsed.elf.elfClass); stmt.setInt(3, parsed.elf.endian)
            stmt.setInt(4, parsed.elf.machine); stmt.setString(5, parsed.sha256); stmt.setString(6, now)
            stmt.setInt(7, parsed.dwarf.units.size); stmt.setInt(8, parsed.elf.sections.size); stmt.executeUpdate()
            stmt.generatedKeys.getLong(1)
        }
        saveWarnings(versionId, parsed.dwarf.warnings)
        saveSections(versionId, parsed.elf)
        saveDwarf(versionId, parsed.dwarf)
        return versionId
    }

    private fun saveWarnings(versionId: Long, warnings: List<Warning>) {
        connection.prepareStatement("insert into warnings(version_id,stage,severity,offset,message) values(?,?,?,?,?)").use { stmt ->
            warnings.forEach { w -> stmt.setLong(1, versionId); stmt.setString(2, w.stage); stmt.setString(3, w.severity); if (w.offset == null) stmt.setNull(4, java.sql.Types.INTEGER) else stmt.setString(4, w.offset.toString()); stmt.setString(5, w.message); stmt.addBatch() }
            stmt.executeBatch()
        }
    }

    private fun saveSections(versionId: Long, elf: ElfFile) {
        connection.prepareStatement("insert into sections(version_id,ordinal,name,type,flags,address,section_offset,size,link,info,alignment,entry_size,sha256) values(?,?,?,?,?,?,?,?,?,?,?,?,?)").use { stmt ->
            elf.sections.forEach { s ->
                stmt.setLong(1, versionId); stmt.setInt(2, s.ordinal); stmt.setString(3, s.name); stmt.setString(4, "0x${s.type.toString(16)}")
                stmt.setString(5, "0x${s.flags.toString(16)}"); stmt.setString(6, s.address.toString()); stmt.setString(7, s.offset.toString())
                stmt.setString(8, s.size.toString()); stmt.setInt(9, s.link); stmt.setInt(10, s.info); stmt.setString(11, s.alignment.toString())
                stmt.setString(12, s.entrySize.toString()); stmt.setString(13, s.sha256); stmt.addBatch()
            }; stmt.executeBatch()
        }
    }

    private fun saveDwarf(versionId: Long, info: DwarfInfo) {
        val cuStmt = connection.prepareStatement("insert into cus(version_id,ordinal,dwarf_offset,size,version_no,unit_type,address_size,segment_size,abbrev_offset,line_offset,low_pc,name,comp_dir,dwo_name,dwo_id,split_status) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS)
        val dieStmt = connection.prepareStatement("insert into dies(cu_id,ordinal,dwarf_offset,tag,tag_name,depth,parent_offset,name,linkage_name,low_pc,high_pc,ranges_offset,call_file,call_line,in_line_value,abstract_origin,specification) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS)
        val rangeStmt = connection.prepareStatement("insert into die_ranges(die_id,start_address,end_address,segment,source,range_ordinal) values(?,?,?,?,?,?)")
        val fileStmt = connection.prepareStatement("insert into source_files(cu_id,ordinal,name,directory,path) values(?,?,?,?,?)")
        val seqStmt = connection.prepareStatement("insert into line_sequences(cu_id,ordinal,start_address,end_address,segment) values(?,?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS)
        val rowStmt = connection.prepareStatement("insert into line_rows(sequence_id,ordinal,address,segment,file_ordinal,file_name,line_no,column_no,isa,discriminator,is_stmt,basic_block,prologue_end,epilogue_begin,end_sequence) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        info.units.forEach { unit ->
            cuStmt.setLong(1, versionId); cuStmt.setInt(2, unit.ordinal); cuStmt.setString(3, unit.offset.toString()); cuStmt.setString(4, unit.size.toString())
            cuStmt.setInt(5, unit.version); cuStmt.setInt(6, unit.unitType); cuStmt.setInt(7, unit.addressSize); cuStmt.setInt(8, unit.segmentSize)
            cuStmt.setString(9, unit.abbrevOffset.toString()); cuStmt.setString(10, unit.lineOffset?.toString()); cuStmt.setString(11, unit.lowPc?.toString())
            cuStmt.setString(12, unit.name); cuStmt.setString(13, unit.compDir); cuStmt.setString(14, unit.dwoName); cuStmt.setString(15, unit.dwoId?.toString()); cuStmt.setString(16, unit.splitStatus); cuStmt.executeUpdate()
            val cuId = cuStmt.generatedKeys.getLong(1)
            unit.nodes.forEach { node ->
                dieStmt.setLong(1, cuId); dieStmt.setInt(2, node.ordinal); dieStmt.setString(3, node.offset.toString()); dieStmt.setInt(4, node.tag); dieStmt.setString(5, node.tagName)
                dieStmt.setInt(6, node.depth); dieStmt.setString(7, node.parentOffset?.toString()); dieStmt.setString(8, node.name); dieStmt.setString(9, node.linkageName)
                dieStmt.setString(10, node.lowPc?.toString()); dieStmt.setString(11, node.highPc?.toString()); dieStmt.setString(12, node.rangesOffset?.toString())
                if (node.callFile == null) dieStmt.setNull(13, java.sql.Types.INTEGER) else dieStmt.setInt(13, node.callFile)
                if (node.callLine == null) dieStmt.setNull(14, java.sql.Types.INTEGER) else dieStmt.setInt(14, node.callLine)
                if (node.inlineValue == null) dieStmt.setNull(15, java.sql.Types.INTEGER) else dieStmt.setInt(15, node.inlineValue)
                dieStmt.setString(16, node.abstractOrigin?.toString()); dieStmt.setString(17, node.specification?.toString()); dieStmt.executeUpdate()
                val dieId = dieStmt.generatedKeys.getLong(1)
                node.ranges.forEach { range ->
                    rangeStmt.setLong(1, dieId); rangeStmt.setString(2, range.start.toString()); rangeStmt.setString(3, range.end.toString()); rangeStmt.setInt(4, range.segment); rangeStmt.setString(5, range.source); rangeStmt.setInt(6, range.ordinal); rangeStmt.addBatch()
                }
            }
            info.linesByCu[unit.ordinal]?.let { lines ->
                lines.files.forEach { file -> fileStmt.setLong(1, cuId); fileStmt.setInt(2, file.ordinal); fileStmt.setString(3, file.name); fileStmt.setString(4, file.directory); fileStmt.setString(5, file.path); fileStmt.addBatch() }
                lines.sequences.forEach { sequence ->
                    seqStmt.setLong(1, cuId); seqStmt.setInt(2, sequence.ordinal); seqStmt.setString(3, sequence.startAddress.toString()); seqStmt.setString(4, sequence.endAddress.toString()); seqStmt.setInt(5, sequence.segment); seqStmt.executeUpdate()
                    val sequenceId = seqStmt.generatedKeys.getLong(1)
                    sequence.rows.forEach { row ->
                        rowStmt.setLong(1, sequenceId); rowStmt.setInt(2, row.ordinal); rowStmt.setString(3, row.address.toString()); rowStmt.setInt(4, row.segment)
                        if (row.fileOrdinal == null) rowStmt.setNull(5, java.sql.Types.INTEGER) else rowStmt.setInt(5, row.fileOrdinal)
                        rowStmt.setString(6, row.fileName); rowStmt.setInt(7, row.line); rowStmt.setInt(8, row.column); rowStmt.setInt(9, row.isa); rowStmt.setInt(10, row.discriminator)
                        rowStmt.setInt(11, if (row.isStmt) 1 else 0); rowStmt.setInt(12, if (row.basicBlock) 1 else 0); rowStmt.setInt(13, if (row.prologueEnd) 1 else 0); rowStmt.setInt(14, if (row.epilogueBegin) 1 else 0); rowStmt.setInt(15, if (row.endSequence) 1 else 0); rowStmt.addBatch()
                    }
                }
            }
        }
        rangeStmt.executeBatch(); fileStmt.executeBatch(); rowStmt.executeBatch()
        listOf(cuStmt, dieStmt, rangeStmt, fileStmt, seqStmt, rowStmt).forEach { it.close() }
    }

    fun closeDb() = connection.close()
    companion object {
        fun defaultPath(): Path = Path.of(System.getProperty("compass.db", "compass-data/compass.db"))
    }
}
