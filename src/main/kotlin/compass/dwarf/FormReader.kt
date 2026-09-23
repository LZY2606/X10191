package compass.dwarf

import compass.elf.ElfFile

/** Reads a single DWARF attribute value given its form. */
class FormReader(
    private val elf: ElfFile,
    private val abbrev: AbbreviationTables,
    private val addrTable: AddrTable,
) {
    private val debugStr = elf.reader(".debug_str")
    private val debugLineStr = elf.reader(".debug_line_str")
    private val debugStrOffsets = elf.reader(".debug_str_offsets")
        ?: elf.reader(".debug_str_offsets.dwo")
    private val debugAddr = elf.reader(".debug_addr") ?: elf.reader(".debug_addr.dwo")

    data class CuContext(
        val version: Int,
        val dwarf64: Boolean,
        val addressSize: Int,
        val cuOffset: Long,
        val strOffsetsBase: Long?,
        val addrBase: Long?,
    )

    fun read(form: Int, implicitConst: Long, r: ByteReader, ctx: CuContext): AttrValue {
        r.dwarf64 = ctx.dwarf64
        r.addressSize = ctx.addressSize
        when (form) {
            Form.ADDR -> return AttrValue.Addr(r.address())
            Form.DATA2 -> return AttrValue.Num(r.u16().toLong())
            Form.DATA4 -> return AttrValue.Num(r.u32())
            Form.DATA8 -> return AttrValue.Num(r.u64())
            Form.DATA1 -> return AttrValue.Num(r.u8().toLong())
            Form.UDATA -> return AttrValue.Num(r.uleb())
            Form.SDATA -> return AttrValue.Num(r.sleb())
            Form.FLAG -> return if (r.u8() != 0) AttrValue.Flag else AttrValue.Num(0)
            Form.FLAG_PRESENT -> return AttrValue.Flag
            Form.STRING -> return AttrValue.Str(r.cString())
            Form.STRP -> {
                val off = if (ctx.dwarf64) r.u64() else r.u32()
                return AttrValue.Str(readDebugStr(off))
            }
            Form.LINE_STRP -> {
                val off = if (ctx.dwarf64) r.u64() else r.u32()
                return AttrValue.Str(readLineStr(off))
            }
            Form.BLOCK -> return AttrValue.Bytes(r.readBytes(r.uleb().toInt()))
            Form.BLOCK1 -> return AttrValue.Bytes(r.readBytes(r.u8()))
            Form.BLOCK2 -> return AttrValue.Bytes(r.readBytes(r.u16()))
            Form.BLOCK4 -> return AttrValue.Bytes(r.readBytes(r.u32().toInt()))
            Form.EXPRLOC -> return AttrValue.Bytes(r.readBytes(r.uleb().toInt()))
            Form.SEC_OFFSET -> return AttrValue.SecOffset(r.dwarfOffset())
            Form.REF1 -> return AttrValue.RefLocal(r.u8().toLong())
            Form.REF2 -> return AttrValue.RefLocal(r.u16().toLong())
            Form.REF4 -> return AttrValue.RefLocal(r.u32())
            Form.REF8 -> return AttrValue.RefLocal(r.u64())
            Form.REF_UDATA -> return AttrValue.RefLocal(r.uleb())
            Form.REF_ADDR -> return AttrValue.RefGlobal(r.dwarfOffset())
            Form.REF_SIG8 -> return AttrValue.Num(r.u64())
            Form.DATA16 -> return AttrValue.Bytes(r.readBytes(16))
            Form.INDIRECT -> {
                val real = r.uleb().toInt()
                if (real == Form.INDIRECT) throw UnknownFormException(form.toLong(), r.sectionOffset())
                return read(real, 0, r, ctx)
            }
            Form.ADDRX, Form.ADDRX1, Form.ADDRX2, Form.ADDRX3, Form.ADDRX4,
            Form.GNU_ADDRX, Form.GNU_ADDRX1, Form.GNU_ADDRX2, Form.GNU_ADDRX3, Form.GNU_ADDRX4 -> {
                val idx = readIndex(form, r)
                return AttrValue.Indexed(AttrValue.IndexKind.ADDRX, idx)
            }
            Form.RNGLISTX, Form.RNGLISTX1, Form.RNGLISTX2, Form.RNGLISTX3, Form.RNGLISTX4,
            Form.GNU_RNGLISTX, Form.GNU_RNGLISTX1, Form.GNU_RNGLISTX2, Form.GNU_RNGLISTX3,
            Form.GNU_RNGLISTX4 -> {
                val idx = readIndex(form, r)
                return AttrValue.Indexed(AttrValue.IndexKind.RNGLISTX, idx)
            }
            Form.STRX, Form.STRX1, Form.STRX2, Form.STRX3, Form.STRX4 -> {
                val idx = readIndex(form, r)
                return resolveStrx(idx, ctx)
            }
            else -> throw UnknownFormException(form.toLong(), r.sectionOffset())
        }
    }

    private fun readIndex(form: Int, r: ByteReader): Long = when (form) {
        Form.ADDRX1, Form.RNGLISTX1, Form.STRX1,
        Form.GNU_ADDRX1, Form.GNU_RNGLISTX1 -> r.u8().toLong()
        Form.ADDRX2, Form.RNGLISTX2, Form.STRX2,
        Form.GNU_ADDRX2, Form.GNU_RNGLISTX2 -> r.u16().toLong()
        Form.ADDRX3, Form.RNGLISTX3, Form.STRX3,
        Form.GNU_ADDRX3, Form.GNU_RNGLISTX3 -> r.readBytes(3).let {
            ((it[0].toLong() and 0xff)) or ((it[1].toLong() and 0xff) shl 8) or
                ((it[2].toLong() and 0xff) shl 16)
        }
        Form.ADDRX4, Form.RNGLISTX4, Form.STRX4,
        Form.GNU_ADDRX4, Form.GNU_RNGLISTX4 -> r.u32()
        else -> r.uleb()
    }

    private fun resolveStrx(idx: Long, ctx: CuContext): AttrValue {
        val base = ctx.strOffsetsBase
        if (base == null || debugStrOffsets == null) {
            return AttrValue.Str("")
        }
        try {
            val r = debugStrOffsets.subReader(debugStrOffsets.base, debugStrOffsets.limit)
            r.seek(base)
            r.dwarf64 = ctx.dwarf64
            val entrySize = if (ctx.dwarf64) 8 else 4
            r.seek(base + idx * entrySize)
            val strOff = r.dwarfOffset()
            return AttrValue.Str(readDebugStr(strOff))
        } catch (_: Exception) {
            return AttrValue.Str("")
        }
    }

    private fun readDebugStr(off: Long): String {
        val s = debugStr ?: return ""
        val r = s.subReader(s.base, s.limit)
        r.seek(off)
        return r.cString()
    }

    private fun readLineStr(off: Long): String {
        val s = debugLineStr ?: return readDebugStr(off)
        val r = s.subReader(s.base, s.limit)
        r.seek(off)
        return r.cString()
    }
}
