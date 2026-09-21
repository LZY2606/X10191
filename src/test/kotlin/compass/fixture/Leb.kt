package compass.fixture

import java.io.ByteArrayOutputStream

object Leb {
    fun uleb(v: Long): ByteArray {
        var x = v
        val out = ByteArrayOutputStream()
        do {
            var b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x != 0L) b = b or 0x80
            out.write(b)
        } while (x != 0L)
        return out.toByteArray()
    }

    fun sleb(v: Long): ByteArray {
        var x = v
        val out = ByteArrayOutputStream()
        var more = true
        while (more) {
            var b = (x and 0x7f).toInt()
            x = x shr 7
            val signBit = b and 0x40
            more = !((x == 0L && signBit == 0) || (x == -1L && signBit != 0))
            if (more) b = b or 0x80
            out.write(b)
        }
        return out.toByteArray()
    }
}

class BytesBuilder {
    private val out = ByteArrayOutputStream()
    fun u8(v: Int) = apply { out.write(v and 0xff) }
    fun u16(v: Int) = apply { out.write(v and 0xff); out.write((v ushr 8) and 0xff) }
    fun u32(v: Long) = apply { repeat(4) { i -> out.write(((v ushr (i * 8)) and 0xff).toInt()) } }
    fun u64(v: Long) = apply { repeat(8) { i -> out.write(((v ushr (i * 8)) and 0xff).toInt()) } }
    fun bytes(b: ByteArray) = apply { out.write(b) }
    fun uleb(v: Long) = apply { out.write(Leb.uleb(v)) }
    fun sleb(v: Long) = apply { out.write(Leb.sleb(v)) }
    fun str(s: String) = apply { out.write(s.toByteArray()); out.write(0) }
    fun cstrBytes(s: String): ByteArray = s.toByteArray() + 0
    val size: Int get() = out.size()
    fun build(): ByteArray = out.toByteArray()
}

/** Length-prefixed (DWARF 32-bit) unit: length covers everything AFTER the 4-byte field. */
fun dwarf32Unit(contentAfterLength: ByteArray): ByteArray =
    BytesBuilder().u32(contentAfterLength.size.toLong()).bytes(contentAfterLength).build()
