package compass.dwarf

class ParseException(message: String, val offset: Long = -1, cause: Throwable? = null) :
    RuntimeException("$message${if (offset >= 0) " @0x${offset.toString(16)}" else ""}", cause)

class UnknownFormException(val form: Int, offset: Long) :
    ParseException("未知/不支持的 DWARF form 0x${form.toString(16)}，中止该 CU 以防游标错位", offset)

class BinReader(val data: ByteArray, var pos: Int = 0, val littleEndian: Boolean = true) {
    val size: Int get() = data.size
    fun u16be(): Int = (u8() shl 8) or u8()
    fun u32be(): Long = (u8().toLong() shl 24) or (u8().toLong() shl 16) or (u8().toLong() shl 8) or u8().toLong()
    fun u64be(): Long { var v = 0L; for (i in 0 until 8) v = (v shl 8) or u8().toLong(); return v }
    fun putWord(p: Int, width: Int, value: Long) {
        for (i in 0 until width) {
            val shift = i * 8
            val b = ((value ushr shift) and 0xff).toInt()
            data[p + if (littleEndian) i else width - 1 - i] = b.toByte()
        }
    }
    fun remaining(): Int = data.size - pos
    fun seek(p: Int): BinReader {
        if (p < 0 || p > data.size) throw ParseException("读取越界: offset=0x${p.toString(16)} size=${data.size}", p.toLong())
        pos = p
        return this
    }
    fun u8(): Int {
        if (pos + 1 > data.size) throw ParseException("u8 越界", pos.toLong())
        return data[pos++].toInt() and 0xff
    }
    fun i8(): Int = (u8() shl 24) >> 24
    fun u16(): Int = if (littleEndian) u8() or (u8() shl 8) else u16be()
    fun i16(): Int = (u16() shl 16) >> 16
    fun u32(): Long = if (littleEndian) (u8().toLong()) or (u8().toLong() shl 8) or (u8().toLong() shl 16) or (u8().toLong() shl 24) else u32be()
    fun i32(): Int = u32().toInt()
    fun u64(): Long = if (littleEndian) u32() or (u32() shl 32) else u64be()
    fun take(n: Int): ByteArray {
        if (n < 0 || pos + n > data.size) throw ParseException("读取 $n 字节越界", pos.toLong())
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }
    fun cstring(): String {
        val start = pos
        while (pos < data.size && data[pos].toInt() != 0) pos++
        if (pos >= data.size) throw ParseException("未终止的字符串", start.toLong())
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }
    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        val start = pos
        while (true) {
            if (++count > maxBytes) throw ParseException("ULEB128 超长", start.toLong())
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw ParseException("ULEB128 溢出", start.toLong())
        }
        return result
    }
    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        val start = pos
        while (true) {
            if (++count > 16) throw ParseException("SLEB128 超长", start.toLong())
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }
    fun uword(width: Int): Long = when (width) {
        1 -> u8().toLong(); 2 -> u16().toLong(); 4 -> u32(); 8 -> u64()
        else -> throw ParseException("非法整数宽度 $width")
    }
}

object DW_TAG {
    const val COMPILE_UNIT = 0x11
    const val INLINED_SUBROUTINE = 0x1d
    const val SUBPROGRAM = 0x2e
    const val TYPE_UNIT = 0x41
}

object DW_AT {
    const val NAME = 0x03
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val STMT_LIST = 0x10
    const val CALL_COLUMN = 0x57
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val COMP_DIR = 0x1b
    const val PRODUCER = 0x25
    const val INLINE = 0x20
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val DECLARATION = 0x3c
    const val RANGES = 0x55
    const val LINKAGE_NAME = 0x6e
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x77
    const val GNU_DWO_NAME = 0x2130
    const val GNU_DWO_ID = 0x2131
    const val GNU_RANGES_BASE = 0x2132
    const val GNU_ADDR_BASE = 0x2133
}

object DW_FORM {
    const val ADDR = 0x01
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val DATA2 = 0x05
    const val DATA4 = 0x06
    const val DATA8 = 0x07
    const val STRING = 0x08
    const val BLOCK = 0x09
    const val BLOCK1 = 0x0a
    const val DATA1 = 0x0b
    const val FLAG = 0x0c
    const val SDATA = 0x0d
    const val STRP = 0x0e
    const val UDATA = 0x0f
    const val REF_ADDR = 0x10
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val INDIRECT = 0x16
    const val SEC_OFFSET = 0x17
    const val EXPRLOC = 0x18
    const val FLAG_PRESENT = 0x19
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOCLISTX = 0x22
    const val RNGLISTX = 0x23
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX1 = 0x29
    const val ADDRX2 = 0x2a
    const val ADDRX3 = 0x2b
    const val ADDRX4 = 0x2c
}

object DW_UT {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
}

object DW_LNS {
    const val COPY = 0x01
    const val ADVANCE_PC = 0x02
    const val ADVANCE_LINE = 0x03
    const val SET_FILE = 0x04
    const val SET_COLUMN = 0x05
    const val NEGATE_STMT = 0x06
    const val SET_BASIC_BLOCK = 0x07
    const val CONST_ADD_PC = 0x08
    const val FIXED_ADVANCE_PC = 0x09
    const val SET_PROLOGUE_END = 0x0a
    const val SET_EPILOGUE_BEGIN = 0x0b
    const val SET_ISA = 0x0c
    const val V5_SET_ADDRESS = 0x00
}

object DW_LNE {
    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
}

object DW_LNCT {
    const val PATH = 0x01
    const val DIRECTORY_INDEX = 0x02
    const val TIMESTAMP = 0x03
    const val SIZE = 0x04
    const val MD5 = 0x05
}

object DW_RLE {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object DW_INL {
    const val NOT_INLINED = 0x00
    const val INLINED = 0x01
    const val DECLARED_NOT_INLINED = 0x02
    const val DECLARED_INLINED = 0x03
}
