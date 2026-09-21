package compass.dwarf

import compass.util.ByteReader
import compass.util.Hex
import compass.util.ParseException
import compass.util.U64

/**
 * Context carried while reading DIE attributes of one compilation unit.
 */
class FormContext(
    val dwarfVersion: Int,
    val dwarf64: Boolean,
    val offsetSize: Int,
    val addressSize: Int,
    val dwo: Boolean,
    /** Absolute offset of the current CU within .debug_info (needed for relative refs). */
    val cuOffset: U64,
    var strOffsetsBase: U64?,
    var addrBase: U64?,
    val debugData: DebugData
)

/** Reads one attribute form; throws ParseException for unknown forms so the CU stops aligned. */
object FormReader {

    fun read(
        r: ByteReader,
        formIn: Int,
        ctx: FormContext,
        implicitValue: Long? = null
    ): AttrValue {
        if (formIn == DwForm.IMPLICIT_CONST) {
            if (implicitValue == null) throw ParseException("DW_FORM_implicit_const without value")
            return if (implicitValue < 0) AttrValue.SConst(implicitValue) else AttrValue.UConst(U64(implicitValue))
        }
        var form = formIn
        var hops = 0
        while (form == DwForm.INDIRECT) {
            if (++hops > 4) throw ParseException("DW_FORM_indirect chain too long")
            form = r.uleb128().toInt()
        }
        return when (form) {
            DwForm.ADDR -> AttrValue.Addr(if (ctx.addressSize == 4) U64(r.u32()) else r.u64())

            DwForm.DATA1 -> AttrValue.UConst(U64(r.u8().toLong()))
            DwForm.DATA2 -> AttrValue.UConst(U64(r.u16().toLong()))
            DwForm.DATA4 -> AttrValue.UConst(U64(r.u32()))
            DwForm.DATA8 -> AttrValue.UConst(r.u64())
            DwForm.UDATA -> AttrValue.UConst(r.ulebU())
            DwForm.SDATA -> AttrValue.SConst(r.sleb128())
            DwForm.FLAG -> AttrValue.Flag(r.u8() != 0)
            DwForm.FLAG_PRESENT -> AttrValue.Flag(true)

            DwForm.STRING -> AttrValue.Str(r.cstring())
            DwForm.LINE_STRP -> {
                val off = readOffset(r, ctx.offsetSize)
                AttrValue.Str(ctx.debugData.readLineString(off.v.toLong(), ctx.dwo))
            }
            DwForm.STRP -> {
                val off = readOffset(r, ctx.offsetSize)
                AttrValue.Str(ctx.debugData.readDebugString(off.v, ctx.dwo))
            }
            DwForm.STRX, DwForm.GNU_STR_INDEX -> {
                val idx = r.uleb128()
                AttrValue.Str(ctx.debugData.resolveStrx(ctx.strOffsetsBase, idx, ctx.offsetSize, ctx.dwarfVersion, ctx.dwo))
            }
            DwForm.STRX1 -> AttrValue.Str(ctx.debugData.resolveStrx(ctx.strOffsetsBase, r.u8().toLong(), ctx.offsetSize, ctx.dwarfVersion, ctx.dwo))
            DwForm.STRX2 -> AttrValue.Str(ctx.debugData.resolveStrx(ctx.strOffsetsBase, r.u16().toLong(), ctx.offsetSize, ctx.dwarfVersion, ctx.dwo))
            DwForm.STRX3 -> {
                require(r.remaining() >= 4)
                AttrValue.Str(ctx.debugData.resolveStrx(ctx.strOffsetsBase, r.u32(), ctx.offsetSize, ctx.dwarfVersion, ctx.dwo))
            }
            DwForm.STRX4 -> AttrValue.Str(ctx.debugData.resolveStrx(ctx.strOffsetsBase, r.u32(), ctx.offsetSize, ctx.dwarfVersion, ctx.dwo))

            DwForm.ADDRX, DwForm.GNU_ADDR_INDEX -> {
                val idx = r.uleb128()
                AttrValue.AddrIndex(U64(idx))
            }
            DwForm.ADDRX1 -> AttrValue.AddrIndex(U64(r.u8().toLong()))
            DwForm.ADDRX2 -> AttrValue.AddrIndex(U64(r.u16().toLong()))
            DwForm.ADDRX3 -> AttrValue.AddrIndex(r.u32u())
            DwForm.ADDRX4 -> AttrValue.AddrIndex(U64(r.u32()))

            DwForm.RNGLISTX -> AttrValue.RngListIndex(r.ulebU())
            DwForm.LOCLISTX -> AttrValue.LocListIndex(r.ulebU())

            DwForm.REF1 -> AttrValue.Ref(U64(r.u8().toLong()))
            DwForm.REF2 -> AttrValue.Ref(U64(r.u16().toLong()))
            DwForm.REF4 -> AttrValue.Ref(U64(r.u32()))
            DwForm.REF8 -> AttrValue.Ref(r.u64())
            DwForm.REF_UDATA -> AttrValue.Ref(r.ulebU())
            DwForm.REF_ADDR -> {
                val off = readOffset(r, ctx.offsetSize)
                AttrValue.Ref(off)
            }
            DwForm.SEC_OFFSET -> AttrValue.SecOff(readOffset(r, ctx.offsetSize))
            DwForm.REF_SIG8 -> AttrValue.Ref(r.u64())
            DwForm.REF_SUP4 -> AttrValue.Ref(U64(r.u32()))
            DwForm.REF_SUP8 -> AttrValue.Ref(r.u64())

            DwForm.EXPRLOC -> {
                val len = r.uleb128().toInt()
                AttrValue.Expr(Hex.encode(r.bytes(len)), null)
            }
            DwForm.BLOCK -> {
                val len = r.uleb128().toInt()
                AttrValue.Expr(Hex.encode(r.bytes(len)), null)
            }
            DwForm.BLOCK1 -> { val len = r.u8(); AttrValue.Expr(Hex.encode(r.bytes(len)), null) }
            DwForm.BLOCK2 -> { val len = r.u16(); AttrValue.Expr(Hex.encode(r.bytes(len)), null) }
            DwForm.BLOCK4 -> { val len = r.u32().toInt(); AttrValue.Expr(Hex.encode(r.bytes(len)), null) }
            DwForm.DATA16 -> AttrValue.Expr(Hex.encode(r.bytes(16)), null)

            else -> throw UnknownFormException(form)
        }
    }

    /**
     * Reads the implicit-constant attribute declarations encoded in the abbreviation table.
     * The abbrev parser keeps (attr, form) pairs; for DW_FORM_implicit_const the value follows
     * directly in .debug_abbrev, so this method is used there.
     */
    fun readAbbrevSdata(r: ByteReader): Long = r.sleb128()

    private fun readOffset(r: ByteReader, offsetSize: Int): U64 =
        if (offsetSize == 4) U64(r.u32()) else r.u64()
}

class UnknownFormException(val form: Int) :
    RuntimeException("unknown/unsupported DWARF form 0x${form.toString(16)}")
