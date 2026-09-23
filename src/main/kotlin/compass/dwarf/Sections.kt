package compass.dwarf

/** Raw bytes of the DWARF sections relevant to the parser. */
class DebugSections(private val map: Map<String, ByteArray>) {
    operator fun get(name: String): ByteArray? = map[name]
    fun require(name: String): ByteArray = map[name] ?: ByteArray(0)
    val names: Set<String> get() = map.keys

    companion object {
        /** Split (.dwo) sections are named *.dwo in the object; map them to logical names. */
        fun of(data: Map<String, ByteArray>): DebugSections {
            val logical = LinkedHashMap<String, ByteArray>()
            for ((k, v) in data) {
                val key = when {
                    k.endsWith(".dwo") -> k.removeSuffix(".dwo")
                    else -> k
                }
                logical.putIfAbsent(key, v)
                // remember .dwo section name under dwo-specific alias too
                if (k.endsWith(".dwo")) logical.putIfAbsent(k, v)
            }
            return DebugSections(logical)
        }
    }
}
