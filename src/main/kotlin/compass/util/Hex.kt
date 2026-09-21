package compass.util

object Hex {
    private val HEX = "0123456789abcdef".toCharArray()
    fun encode(bytes: ByteArray, max: Int = bytes.size): String {
        val n = minOf(bytes.size, max)
        val sb = StringBuilder(n * 2)
        for (i in 0 until n) {
            val b = bytes[i].toInt() and 0xff
            sb.append(HEX[b ushr 4]).append(HEX[b and 0x0f])
        }
        return sb.toString()
    }
}
