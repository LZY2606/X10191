package compass.dwarf

import compass.elf.Cursor
import compass.elf.sleb128
import compass.elf.uleb128

/** A decoded attribute value, tagged so callers can distinguish pc/offset/string/flag. */
sealed class FormValue {
    data class Addr(val v: ULong) : FormValue()
    data class Number(val v: Long) : FormValue()
    data class Str(val v: String) : FormValue()
    data class SecOffset(val v: Long) : FormValue()
    data class Block(val bytes: ByteArray, val implicitConst: Boolean = false) : FormValue() {
        override fun equals(other: Any?) = other is Block && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
    /** Form not recognized; [consumed] bytes were skipped to keep the cursor aligned. */
    data class Unknown(val form: Int, val consumed: Int) : FormValue()
    data class Exprloc(val bytes: ByteArray) : FormValue() {
        override fun equals(other: Any?) = other is Exprloc && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }

    val asLong: Long?
        get() = when (this) {
            is Addr -> v.toLong()
            is Number -> v
            is SecOffset -> v
            else -> null
        }
    val asString: String? get() = (this as? Str)?.v
}

data class Attribute(val name: Int, val form: Int, val value: FormValue)

data class Die(
    val offset: Int,
    val tag: Int,
    val attributes: List<Attribute>,
    val depth: Int,
    val children: List<Die>,
    var cuIndex: Int = -1,
) {
    fun attr(n: Int): Attribute? = attributes.firstOrNull { it.name == n }
    fun hasChildren(): Boolean = children.isNotEmpty()
    val name: String? get() = attr(Attr.NAME)?.value?.asString
}

data class AbbrevDecl(val code: Int, val tag: Int, val hasChildren: Boolean, val specs: List<Pair<Int, Int>>)

class AbbrevTable(private val decls: Map<Int, AbbrevDecl>) {
    operator fun get(code: Int): AbbrevDecl? = decls[code]

    companion object {
        /** Parse one abbreviation table starting at [start], terminating at the zero byte. */
        fun parse(c: Cursor, start: Int): AbbrevTable {
            c.seek(start)
            val decls = LinkedHashMap<Int, AbbrevDecl>()
            while (true) {
                if (c.remaining <= 0) throw DwarfParseException("abbrev table runs past section end")
                val code = c.uleb128().toInt()
                if (code == 0) break
                val tag = c.uleb128().toInt()
                val hasChildren = c.u8() == 1
                val specs = ArrayList<Pair<Int, Int>>()
                while (true) {
                    val attr = c.uleb128().toInt()
                    val form = c.uleb128().toInt()
                    if (attr == 0 && form == 0) break
                    specs.add(attr to form)
                    if (form == Form.IMPLICIT_CONST) {
                        // implicit_const carries an SLEB value inline in the abbrev itself.
                        c.sleb128()
                    }
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, specs)
            }
            return AbbrevTable(decls)
        }
    }
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
