package compass.dwarf

import java.security.MessageDigest

object Util {
    private val HEX = "0123456789abcdef".toCharArray()
    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0f]
        }
        return String(out)
    }

    fun sha256(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun shortDigest(bytes: ByteArray, len: Int = 16): String = sha256(bytes).take(len * 2)

    fun ulong(v: Long): ULong = v.toULong()
    fun unsignedLess(a: Long, b: Long): Boolean = a.toULong() < b.toULong()
    fun unsignedLeq(a: Long, b: Long): Boolean = a.toULong() <= b.toULong()
    fun unsignedSub(a: Long, b: Long): Long = (a.toULong() - b.toULong()).toLong()
    fun unsignedAdd(a: Long, b: Long): Long = (a.toULong() + b.toULong()).toLong()
    fun width(lo: Long, hi: Long): ULong = hi.toULong() - lo.toULong()
}
