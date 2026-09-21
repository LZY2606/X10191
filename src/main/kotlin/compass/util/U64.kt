package compass.util

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * 64-bit unsigned address/offset. Stored in JSON as a 0x-prefixed hex string so that
 * browser JavaScript never loses high-bit precision.
 */
@Serializable(with = U64HexSerializer::class)
@JvmInline
value class U64(val v: Long) : Comparable<U64> {
    operator fun plus(other: Long): U64 = U64(v + other)
    operator fun plus(other: U64): U64 = U64(v + other.v)
    operator fun minus(other: U64): U64 = U64(v - other.v)
    fun diff(other: U64): Long = v - other.v
    override fun compareTo(other: U64): Int = java.lang.Long.compareUnsigned(v, other.v)
    fun toHex(): String = java.lang.Long.toUnsignedString(v, 16)
    override fun toString(): String = "0x" + toHex()

    companion object {
        val ZERO = U64(0L)
        val MAX = U64(-1L)
        fun parse(raw: String): U64 {
            val s = raw.trim().removePrefix("0x").removePrefix("0X")
            if (s.isEmpty()) return ZERO
            return U64(java.lang.Long.parseUnsignedLong(s, if (s.any { it.isDigit() && it > '9' || it in 'a'..'f' || it in 'A'..'F' }) 16 else 10))
        }
    }
}

object U64HexSerializer : KSerializer<U64> {
    override val descriptor = PrimitiveSerialDescriptor("compass.util.U64", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: U64) = encoder.encodeString("0x" + value.toHex())
    override fun deserialize(decoder: Decoder): U64 = U64.parse(decoder.decodeString())
}
