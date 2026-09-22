package compass

import java.security.MessageDigest

fun ByteArray.sha256Hex(): String {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(this).joinToString("") { "%02x".format(it) }
}

fun String.shortHash(): String = if (length <= 12) this else substring(0, 12)

/** Parses "0x10c0", "10c0", "4256" as hex when prefixed with 0x or $, else decimal. */
fun parseAddress(text: String): Long {
    var t = text.trim().lowercase()
    if (t.isEmpty()) throw IllegalArgumentException("empty address")
    return when {
        t.startsWith("0x") -> t.substring(2).toULong(16).toLong()
        t.startsWith("$") -> t.substring(1).toULong(16).toLong()
        t.startsWith("+") -> t.substring(1).toLong()
        else -> t.toLong()
    }
}

fun Long.hex(): String = "0x" + java.lang.Long.toHexString(this)

object Limits {
    const val MAX_DIE_DEPTH = 64
    const val MAX_REF_DEPTH = 8
    const val MAX_ABBREV_ATTRS = 512
    const val MAX_ABBREV_CODES = 100_000
    const val MAX_DIES_PER_CU = 500_000
    const val MAX_LINE_ROWS = 2_000_000
    const val MAX_FILE_ENTRIES = 200_000
    const val MAX_STRING = 1 shl 20
    const val MAX_BLOCK = 1 shl 24
    const val MAX_RANGES = 1_000_000
    const val MAX_INDIRECT = 4
}
