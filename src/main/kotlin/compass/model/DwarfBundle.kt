package compass.model

import compass.dwarf.CompileUnit
import compass.dwarf.DwarfCursor
import compass.dwarf.DwarfParseException
import compass.elf.ElfFile
import compass.elf.ElfParser
import java.security.MessageDigest

/**
 * Everything parsed from one imported ELF + detached debug link file.
 * Sections are raw bytes extracted at import time (snapshot).
 */
class DwarfBundle(
    val elf: ElfFile,
    /** additional sections contributed by a detached .debug file (ELF). */
    val debugElf: ElfFile?,
    val compileUnits: List<CompileUnit>,
) {
    fun section(name: String): ByteArray? =
        elf.sectionBytes(name) ?: debugElf?.sectionBytes(name)

    val fileName: String get() = elf.section(".debug_info")?.let { "elf" } ?: "debug"

    val isDwarf5Any: Boolean get() = compileUnits.any { it.version == 5 }
}

object BundleLoader {
    fun sha256(data: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    /** Parse main ELF plus an optional detached debug ELF. Split DWARF dwo lookup happens later. */
    fun load(main: ByteArray, debugFile: ByteArray? = null): DwarfBundle {
        val mainElf = ElfParser.parse(main, sha256(main))
        val dbg = debugFile?.let { ElfParser.parse(it, sha256(it)) }
        val bundle0 = DwarfBundle(mainElf, dbg, emptyList())
        val units = try {
            compass.dwarf.InfoParser(bundle0).parseAll()
        } catch (e: Exception) {
            throw DwarfParseException("failed to parse .debug_info: ${e.message}", e)
        }
        return DwarfBundle(mainElf, dbg, units)
    }
}

/** Resolve strings from .debug_str / .debug_line_str, honoring str_offsets (DWARF5). */
class StringResolver(private val bundle: DwarfBundle) {
    private val debugStr = bundle.section(".debug_str")
    private val lineStr = bundle.section(".debug_line_str")

    fun at(offset: Long): String? {
        val sec = debugStr ?: return null
        if (offset < 0 || offset >= sec.size) return null
        return runCatching { DwarfCursor(sec, offset.toInt()).cstring() }.getOrNull()
    }

    fun lineAt(offset: Long): String? {
        val sec = lineStr ?: return at(offset)
        if (offset < 0 || offset >= sec.size) return null
        return runCatching { DwarfCursor(sec, offset.toInt()).cstring() }.getOrNull()
    }

    /**
     * Resolve a strx index using the CU's str_offsets base. The base header
     * itself is small; we locate it from DW_AT_str_offsets_base when present,
     * otherwise derive from the first contribution in .debug_str_offsets.
     */
    fun strx(cu: CompileUnit, index: Long): String? {
        val sec = bundle.section(".debug_str_offsets") ?: return null
        val baseAttr = cu.root.attr(compass.dwarf.DwAt.STR_OFFSETS_BASE)
        val entryWidth = cu.addressSize.coerceAtLeast(4)
        val base: Long = when (val v = baseAttr?.value) {
            is compass.dwarf.RawValue.Num -> v.v
            is compass.dwarf.RawValue.RngListOffset -> v.offset
            else -> findStrOffsetsContribution(cu)
        }
        val off = base + index * entryWidth
        if (off < 0 || off + entryWidth > sec.size) return null
        val target = DwarfCursor(sec, off.toInt()).fixed(entryWidth)
        return at(target)
    }

    private val strContribCache = HashMap<Long, Long>()

    private fun findStrOffsetsContribution(cu: CompileUnit): Long {
        strContribCache[cu.offset]?.let { return it }
        val sec = bundle.section(".debug_str_offsets") ?: return -1
        val c = DwarfCursor(sec)
        var fallback = 0L
        while (!c.atEnd()) {
            val start = c.pos.toLong()
            try {
                val lenW = c.u32()
                val is64 = lenW == 0xffffffffL
                val length = if (is64) c.u64() else lenW
                val end = start + length + (if (is64) 12 else 4)
                if (cu.version >= 5) {
                    c.u16(); c.u16(); c.u8(); c.u8()
                }
                fallback = c.pos.toLong()
                if (start == 0L) {
                    strContribCache[cu.offset] = fallback
                    return fallback
                }
                c.seek(end)
            } catch (e: Exception) {
                break
            }
        }
        return fallback
    }
}

/** .debug_addr table resolution (DWARF5 / GNU extensions). */
class AddrTableResolver(private val bundle: DwarfBundle) {
    fun resolve(cu: CompileUnit, index: Long): Long? {
        val sec = bundle.section(".debug_addr") ?: return null
        val baseAttr = cu.root.attr(compass.dwarf.DwAt.ADDR_BASE)
        val width = cu.addressSize.coerceAtLeast(4)
        val base: Long = when (val v = baseAttr?.value) {
            is compass.dwarf.RawValue.Num -> v.v
            else -> findAddrContribution()
        }
        val off = base + index * width
        if (off < 0 || off + width > sec.size) return null
        return DwarfCursor(sec, off.toInt()).fixed(width)
    }

    private fun findAddrContribution(): Long {
        val sec = bundle.section(".debug_addr") ?: return -1
        val c = DwarfCursor(sec)
        if (c.size < 8) return -1
        val lenW = c.u32()
        val is64 = lenW == 0xffffffffL
        return if (is64) { c.u64(); c.u16(); c.u8(); c.u8(); c.pos.toLong() }
        else { c.u16(); c.u8(); c.u8(); c.pos.toLong() }
    }
}
