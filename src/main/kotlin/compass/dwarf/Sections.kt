@file:Suppress("ArrayInDataClass")
package compass.dwarf

/** Raw debug sections from one ELF file. Both normal and .dwo section names are supported. */
class Sections(private val map: Map<String, ByteArray>) {
    operator fun get(name: String): ByteArray? = map[name]
    fun names(): Set<String> = map.keys
    fun has(name: String): Boolean = map[name]?.isNotEmpty() == true

    companion object {
        fun of(map: Map<String, ByteArray>) = Sections(map)
    }
}
