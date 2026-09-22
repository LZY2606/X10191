package compass

/** Minimal JSON writer (no external dependency). */
object Json {
    fun escape(s: String): String = buildString(s.length + 8) {
        append('"')
        for (c in s) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
        }
        append('"')
    }

    class Obj {
        private val fields = LinkedHashMap<String, String>()
        fun put(k: String, v: String?) = apply { fields[k] = if (v == null) "null" else escape(v) }
        fun put(k: String, v: Long) = apply { fields[k] = v.toString() }
        fun put(k: String, v: Int) = apply { fields[k] = v.toString() }
        fun put(k: String, v: Boolean) = apply { fields[k] = v.toString() }
        fun putHex(k: String, v: Long) = apply { fields[k] = escape("0x" + v.toString(16)) }
        fun putRaw(k: String, rawJson: String) = apply { fields[k] = rawJson }
        fun put(k: String, v: Obj) = apply { fields[k] = v.toString() }
        fun put(k: String, arr: Arr) = apply { fields[k] = arr.toString() }
        fun putStrings(k: String, items: List<String>) = apply {
            fields[k] = items.joinToString(",", "[", "]") { escape(it) }
        }
        override fun toString() = fields.entries.joinToString(",", "{", "}") { "${escape(it.key)}:${it.value}" }
    }

    class Arr {
        private val items = ArrayList<String>()
        fun add(v: Obj) = apply { items.add(v.toString()) }
        fun add(v: String) = apply { items.add(escape(v)) }
        fun add(v: Long) = apply { items.add(v.toString()) }
        fun addRaw(raw: String) = apply { items.add(raw) }
        override fun toString() = items.joinToString(",", "[", "]")
    }

    fun obj(build: Obj.() -> Unit): Obj = Obj().apply(build)
    fun arr(build: Arr.() -> Unit): Arr = Arr().apply(build)
}
