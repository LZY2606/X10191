package compass.query

import java.sql.Connection
import java.sql.DriverManager

/** SQLite-backed persistence. Old crash records and imports are never mutated. */
class Store(path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    init {
        conn.autoCommit = true
        conn.createStatement().use { st ->
            st.executeUpdate("PRAGMA journal_mode=WAL")
            st.executeUpdate("PRAGMA foreign_keys=ON")
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_file(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  sha256 TEXT NOT NULL,
                  size INTEGER NOT NULL,
                  imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                  notes TEXT NOT NULL DEFAULT ''
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS section(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  name TEXT NOT NULL,
                  type INTEGER NOT NULL,
                  flags INTEGER NOT NULL,
                  addr INTEGER NOT NULL,
                  offset INTEGER NOT NULL,
                  size INTEGER NOT NULL,
                  sha256 TEXT NOT NULL
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS cu(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  cu_index INTEGER NOT NULL,
                  offset INTEGER NOT NULL,
                  version INTEGER NOT NULL,
                  unit_type INTEGER NOT NULL,
                  address_size INTEGER NOT NULL,
                  name TEXT,
                  comp_dir TEXT,
                  producer TEXT,
                  dwo_name TEXT,
                  low_pc INTEGER,
                  stmt_list INTEGER,
                  degraded INTEGER NOT NULL DEFAULT 0,
                  notes TEXT NOT NULL DEFAULT ''
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS line_sequence(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  cu_id INTEGER NOT NULL REFERENCES cu(id),
                  seq_index INTEGER NOT NULL,
                  start INTEGER NOT NULL,
                  end INTEGER NOT NULL
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS line_row(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sequence_id INTEGER NOT NULL REFERENCES line_sequence(id),
                  address INTEGER NOT NULL,
                  file TEXT,
                  line INTEGER NOT NULL,
                  col INTEGER NOT NULL,
                  is_stmt INTEGER NOT NULL,
                  end_seq INTEGER NOT NULL,
                  basic_block INTEGER NOT NULL,
                  prologue_end INTEGER NOT NULL,
                  epilogue_begin INTEGER NOT NULL,
                  discriminator INTEGER NOT NULL
                )"""
            )
            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_line_row_seq ON line_row(sequence_id, address)")
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS scope(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  cu_id INTEGER NOT NULL REFERENCES cu(id),
                  die_offset INTEGER NOT NULL,
                  tag INTEGER NOT NULL,
                  name TEXT,
                  depth INTEGER NOT NULL,
                  parent_id INTEGER,
                  call_file TEXT,
                  call_line INTEGER,
                  call_column INTEGER
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS scope_range(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scope_id INTEGER NOT NULL REFERENCES scope(id),
                  start INTEGER NOT NULL,
                  end INTEGER NOT NULL
                )"""
            )
            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_scope_range ON scope_range(start, end)")
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshot(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  label TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshot_module(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  snapshot_id INTEGER NOT NULL REFERENCES snapshot(id),
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  load_bias INTEGER NOT NULL,
                  priority INTEGER NOT NULL DEFAULT 0,
                  generation INTEGER NOT NULL
                )"""
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS query_log(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  snapshot_id INTEGER NOT NULL,
                  raw_address INTEGER NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  result_json TEXT NOT NULL
                )"""
            )
        }
    }

    fun <T> tx(block: () -> T): T {
        conn.autoCommit = false
        try {
            val v = block()
            conn.commit()
            return v
        } catch (e: Exception) {
            conn.rollback()
            throw e
        } finally {
            conn.autoCommit = true
        }
    }

    fun insert(sql: String, vararg args: Any?): Long {
        conn.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            bind(ps, args)
            ps.executeUpdate()
            ps.generatedKeys.use { rs -> return if (rs.next()) rs.getLong(1) else -1L }
        }
    }

    fun exec(sql: String, vararg args: Any?) {
        conn.prepareStatement(sql).use { ps ->
            bind(ps, args)
            ps.executeUpdate()
        }
    }

    fun query(sql: String, vararg args: Any?, row: (java.sql.ResultSet) -> Unit) {
        conn.prepareStatement(sql).use { ps ->
            bind(ps, args)
            ps.executeQuery().use { rs -> while (rs.next()) row(rs) }
        }
    }

    fun <T> queryList(sql: String, vararg args: Any?, row: (java.sql.ResultSet) -> T): List<T> {
        val out = ArrayList<T>()
        query(sql, *args) { rs -> out.add(row(rs)) }
        return out
    }

    private fun bind(ps: java.sql.PreparedStatement, args: Array<out Any?>) {
        args.forEachIndexed { i, a ->
            when (a) {
                null -> ps.setObject(i + 1, null)
                is Long -> ps.setLong(i + 1, a)
                is Int -> ps.setInt(i + 1, a)
                is String -> ps.setString(i + 1, a)
                is Boolean -> ps.setBoolean(i + 1, a)
                else -> ps.setString(i + 1, a.toString())
            }
        }
    }
}
