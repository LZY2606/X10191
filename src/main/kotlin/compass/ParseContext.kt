package compass

/**
 * Parsing context for one ELF file. The parser reads CU headers/DIEs from this file's sections;
 * rnglists/addr tables in split CUs come from the .dwo file through [splitCtx].
 */
class ParseContext(
    val store: SectionStore,
    val fileName: String,
    val splitCtx: ParseContext? = null,
    val altCtx: ParseContext? = null,
) {
    var cu: CompilationUnitBuilder? = null

    val offsetSize: Int get() = cu?.offsetSize ?: 8

    fun sectionAny(vararg names: String): Pair<String, ByteArray>? = store.bytesAny(*names)

    fun readString(sectionName: String, offset: Long): String {
        val sec = store.bytes(sectionName) ?: altCtx?.store?.bytes(sectionName)
        ?: throw CursorException("$sectionName: section missing for offset $offset")
        if (offset < 0 || offset >= sec.size) throw CursorException("$sectionName: offset $offset out of bounds")
        val c = ByteCursor(sec, offset.toInt(), sec.size, sectionName)
        return c.cString()
    }

    fun readIndexedString(index: Long): String {
        val base = cu?.strOffsetsBase ?: throw CursorException("strx: no str_offsets base")
        val offs = (if (cu?.dwarf5 == true) store.bytes(".debug_str_offsets") else store.bytes(".debug_str_offsets"))
            ?: splitCtx?.store?.bytes(".debug_str_offsets")
            ?: throw CursorException("strx: .debug_str_offsets missing")
        val offSize = cu?.offsetSize ?: 4
        val strOff = StrOffsetsReader(offs).get(base, index, offSize)
        val strSec = store.bytes(".debug_str") ?: splitCtx?.store?.bytes(".debug_str")
        ?: throw CursorException("strx: .debug_str missing")
        if (strOff >= strSec.size) throw CursorException("strx: resolved offset $strOff out of bounds")
        return ByteCursor(strSec, strOff.toInt(), strSec.size, ".debug_str").cString()
    }

    fun readAddrIndex(index: Long): TargetAddress {
        // In a split CU the .debug_addr lives in the .dwo (or linked dwp); skeleton provides addr via ranges instead.
        val base = cu?.addrBase ?: throw CursorException("addrx: DW_AT_addr_base missing")
        val asz = cu?.addressSize ?: 8
        val gnu = cu?.dwarf5 != true
        val local = store.bytes(".debug_addr") ?: splitCtx?.store?.bytes(".debug_addr")
        ?: throw CursorException("addrx: .debug_addr missing (dwo companion present?)")
        return AddrTableReader(local).get(base, index, asz, gnu)
    }
}
