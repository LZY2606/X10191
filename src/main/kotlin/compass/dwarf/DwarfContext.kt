package compass.dwarf

import compass.elf.ByteReader
import compass.elf.EndOfDataException

/**
 * 一次解析所需的全部 section 字节（可来自主文件或 .dwo 文件）。
 * split CU 解析时 [addrSectionForSplit] 由骨架文件的 .debug_addr 提供。
 */
class DwarfContext(
    val info: ByteArray?,
    val abbrev: ByteArray?,
    val line: ByteArray?,
    val str: ByteArray?,
    val lineStr: ByteArray?,
    val ranges: ByteArray?,
    val rnglists: ByteArray?,
    val addr: ByteArray?,
    val strOffsets: ByteArray?,
    val abbrevDwo: ByteArray?,
    val infoDwo: ByteArray?,
    val lineDwo: ByteArray?,
    val strDwo: ByteArray?,
    val lineStrDwo: ByteArray?,
    val rnglistsDwo: ByteArray?,
    val strOffsetsDwo: ByteArray?,
    val littleEndian: Boolean = true,
)

/** 单个 CU 的动态解码上下文：地址宽度、64bit DWARF、字符串/地址/rnglist 基址。 */
class CuDecodeContext(
    val ctx: DwarfContext,
    val version: Int,
    val is64: Boolean,
    val addressSize: Int,
    var strOffsetsBase: Long,
    var addrBase: Long,
    var rnglistsBase: Long,
) {
    fun sectionReader(bytes: ByteArray?): ByteReader? = bytes?.let { ByteReader(it, ctx.littleEndian) }

    fun readStrp(offset: Long, line: Boolean): String {
        val bytes = if (line) {
            ctx.lineStr ?: return "(no .debug_line_str)"
        } else {
            ctx.str ?: return "(no .debug_str)"
        }
        if (offset < 0 || offset >= bytes.size) throw EndOfDataException("strp offset $offset out of section")
        return ByteReader(bytes, ctx.littleEndian, offset.toInt(), bytes.size - offset.toInt()).cString()
    }

    /** DW_FORM_strx* 经 .debug_str_offsets 间接取字符串。 */
    fun readStrx(index: Long): String {
        val bytes = ctx.strOffsets ?: throw EndOfDataException(".debug_str_offsets missing for strx")
        val entrySize = if (is64) 8 else 4
        val pos = strOffsetsBase + index * entrySize
        if (pos < 0 || pos + entrySize > bytes.size) {
            throw EndOfDataException("strx index $index out of .debug_str_offsets (base=$strOffsetsBase)")
        }
        val er = ByteReader(bytes, ctx.littleEndian, pos.toInt(), entrySize)
        val strOff = if (entrySize == 4) er.u32asLong() else er.u64()
        val s = ctx.str ?: throw EndOfDataException(".debug_str missing")
        if (strOff >= s.size) throw EndOfDataException("strx target $strOff out of .debug_str")
        return ByteReader(s, ctx.littleEndian, strOff.toInt(), s.size - strOff.toInt()).cString()
    }

    /** DW_FORM_addrx* 经 .debug_addr 取地址（v5；split CU 共享骨架的 .debug_addr）。 */
    fun readAddrx(index: Long, selector: Long = 0L): SegAddr {
        val bytes = ctx.addr ?: throw EndOfDataException(".debug_addr missing for addrx")
        val pos = addrBase + index * addressSize
        if (pos < 0 || pos + addressSize > bytes.size) {
            throw EndOfDataException("addrx index $index out of .debug_addr (base=$addrBase)")
        }
        val er = ByteReader(bytes, ctx.littleEndian, pos.toInt(), addressSize)
        val off = when (addressSize) {
            1 -> er.u8().toLong()
            2 -> er.u16().toLong()
            4 -> er.u32asLong()
            8 -> er.u64()
            else -> throw EndOfDataException("unsupported address size $addressSize")
        }
        return SegAddr(selector, off)
    }

    fun readAddress(r: ByteReader): SegAddr {
        val off = when (addressSize) {
            1 -> r.u8().toLong()
            2 -> r.u16().toLong()
            4 -> r.u32asLong()
            8 -> r.u64()
            else -> throw EndOfDataException("unsupported address size $addressSize")
        }
        return SegAddr.flat(off)
    }
}

/** 未知/无法解码的 form：调用方必须立即停止当前 CU 的 DIE 读取，避免游标错位。 */
class UnknownFormException(val form: Int, message: String) : RuntimeException(message)
