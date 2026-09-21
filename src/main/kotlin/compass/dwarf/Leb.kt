package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ParseException

object Leb {
    const val MAX_BYTES = 16

    fun uleb(r: ByteReader, what: String = "uleb128"): Long {
        var result = 0L
        var shift = 0
        var i = 0
        while (true) {
            if (++i > MAX_BYTES) throw ParseException("uleb128 超过 $MAX_BYTES 字节 ($what)")
            val b = r.u8(what)
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw ParseException("uleb128 溢出 ($what)")
        }
        return result
    }

    fun sleb(r: ByteReader, what: String = "sleb128"): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var i = 0
        while (true) {
            if (++i > MAX_BYTES) throw ParseException("sleb128 超过 $MAX_BYTES 字节 ($what)")
            b = r.u8(what)
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ParseException("sleb128 溢出 ($what)")
        }
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-1L shl shift)
        }
        return result
    }
}
