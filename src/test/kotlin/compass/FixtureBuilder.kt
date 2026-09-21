package compass

import compass.dwarf.*

import java.io.ByteArrayOutputStream

/**
 * Builds minimal, valid ELF64-LE files containing hand-crafted DWARF sections.
 * This lets tests cover exact edge cases (special opcodes, overlapping ranges,
 * zero-length ranges, high_pc dual meaning, DWARF4 vs DWARF5, missing .dwo,
 * unknown forms, out-of-bounds refs) without depending on a compiler.
 */
class FixtureBuilder {
    private val sections = LinkedHashMap<String, ByteArray>()
    var machine = 0x3e
    var type = 1 // ET_REL

    fun section(name: String, bytes: ByteArray): FixtureBuilder { sections[name] = bytes; return this }
    fun section(name: String, s: ByteArrayBuilder.() -> Unit): FixtureBuilder {
        sections[name] = ByteArrayBuilder().apply(s).build(); return this
    }

    fun build(): ByteArray = ElfAssembler.assemble(sections, machine, type)
}

/** Little-endian byte assembler with ULEB/SLEB helpers. */
class ByteArrayOutputStream2 : ByteArrayOutputStream() {
    fun u8(v: Int) = write(v and 0xff)
    fun u16(v: Int) { write(v and 0xff); write((v ushr 8) and 0xff) }
    fun u32(v: Long) { repeat(4) { i -> write(((v ushr (8 * i)) and 0xff).toInt()) } }
    fun u64(v: Long) { repeat(8) { i -> write(((v ushr (8 * i)) and 0xff).toInt()) } }
    fun bytes(b: ByteArray) = write(b)
    fun cstr(s: String) { write(s.toByteArray()); write(0) }
    fun uleb(v: Int) = uleb(v.toLong())
    fun uleb(v: Long) {
        var x = v
        while (true) {
            var b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x != 0L) b = b or 0x80
            write(b)
            if (x == 0L) break
        }
    }
    fun build(): ByteArray = toByteArray()

    fun sleb(v: Int) = sleb(v.toLong())
    fun sleb(v: Long) {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            val sign = b and 0x40 != 0
            x = x shr 7
            if ((x == 0L && !sign) || (x == -1L && sign)) { write(b); return }
            write(b or 0x80)
        }
    }
}

typealias ByteArrayBuilder = ByteArrayOutputStream2

/** Minimal, strictly-layout ELF64 little-endian assembler (ET_REL/ET_EXEC). */
object ElfAssembler {
    private const val EH_SIZE = 64
    private const val SH_SIZE = 64

    fun assemble(sectionsInput: Map<String, ByteArray>, machine: Int, type: Int): ByteArray {
        val ordered = LinkedHashMap<String, ByteArray>()
        ordered[""] = ByteArray(0)
        sectionsInput.forEach { (k, v) -> ordered[k] = v }

        // shstrtab
        val strtab = buildStringTable(ordered.keys.toList())
        ordered[".shstrtab"] = strtab.bytes

        data class Pos(val name: String, val off: Long, val bytes: ByteArray, val alloc: Boolean)
        val positions = ArrayList<Pos>()
        var cursor = EH_SIZE
        for ((name, bytes) in ordered) {
            if (name.isEmpty()) { positions.add(Pos(name, 0, bytes, false)); continue }
            positions.add(Pos(name, cursor.toLong(), bytes, name == ".text" || name == ".data"))
            cursor += bytes.size
        }
        val shoff = cursor.toLong()
        val shnum = positions.size
        val shstrndx = positions.indexOfFirst { it.name == ".shstrtab" }

        val o = ByteWriter()
        // ---- e_ident ----
        o.byte(0x7f); o.byte('E'.code); o.byte('L'.code); o.byte('F'.code)
        o.byte(2)   // EI_CLASS = ELFCLASS64
        o.byte(1)   // EI_DATA  = ELFDATA2LSB
        o.byte(1)   // EI_VERSION
        o.byte(0)   // EI_OSABI
        o.byte(0)   // EI_ABIVERSION
        repeat(7) { o.byte(0) } // padding -> 16 total
        // ---- header fields ----
        o.leb16(type); o.leb16(machine); o.leb32(1)
        o.leb64(0)               // e_entry   @0x18
        o.leb64(0)               // e_phoff   @0x20
        o.leb64(shoff)           // e_shoff   @0x28
        o.leb32(0)               // e_flags   @0x30
        o.leb16(EH_SIZE)         // e_ehsize  @0x34
        o.leb16(0); o.leb16(0)   // e_phentsize, e_phnum @0x36
        o.leb16(SH_SIZE)         // e_shentsize @0x3a
        o.leb16(shnum)           // e_shnum     @0x3c
        o.leb16(shstrndx)        // e_shstrndx  @0x3e
        check(o.pos == EH_SIZE) { "eh size ${o.pos}" }

        for (p in positions) if (p.bytes.isNotEmpty()) o.raw(p.bytes)

        for (p in positions) {
            val sh = ByteWriter()
            sh.leb32(strtab.indexOf(p.name)) // sh_name
            sh.leb32(if (p.name == ".shstrtab") 3 else 1) // SHT_STRTAB : SHT_PROGBITS
            sh.leb64(if (p.alloc) 2L else 0L)
            sh.leb64(if (p.alloc) p.off else 0L)
            sh.leb64(if (p.bytes.isEmpty()) 0L else p.off)
            sh.leb64(p.bytes.size.toLong())
            sh.leb32(0) // link
            sh.leb32(0) // info
            sh.leb64(1) // addralign
            sh.leb64(0) // entsize
            check(sh.pos == SH_SIZE) { "sh size ${sh.pos}" }
            o.raw(sh.toByteArray())
        }
        return o.toByteArray()
    }

    private class ByteWriter {
        var pos = 0; private val out = java.io.ByteArrayOutputStream()
        fun byte(v: Int) { out.write(v and 0xff); pos++ }
        fun leb16(v: Int) { repeat(2) { i -> byte((v ushr (8 * i)) and 0xff) } }
        fun leb32(v: Int) { repeat(4) { i -> byte((v ushr (8 * i)) and 0xff) } }
        fun leb32(v: Long) { repeat(4) { i -> byte(((v ushr (8 * i)) and 0xff).toInt()) } }
        fun leb64(v: Long) { repeat(8) { i -> byte(((v ushr (8 * i)) and 0xff).toInt()) } }
        fun raw(b: ByteArray) { out.write(b); pos += b.size }
        fun toByteArray() = out.toByteArray()
    }

    private class StringTable(val bytes: ByteArray, private val index: Map<String, Int>) {
        fun indexOf(name: String): Int = index[name] ?: 0
    }

    private fun buildStringTable(names: List<String>): StringTable {
        val b = ByteWriter(); val idx = HashMap<String, Int>()
        b.byte(0) // leading NUL
        for (n in names) {
            if (n.isEmpty() || n in idx) continue
            idx[n] = b.pos
            b.raw(n.toByteArray()); b.byte(0)
        }
        return StringTable(b.toByteArray(), idx)
    }
}

// ---- DWARF builders used by tests ----

object DwarfFixtures {

    /** Abbreviation set: CU root + subprogram + inlined_subroutine. */
    fun abbrevSet(version: Int, config: AbbrevConfig = AbbrevConfig()): ByteArray {
        val b = ByteArrayBuilder()
        // code 1: compile unit
        b.uleb(1); b.uleb(0x11); b.u8(1) // DW_TAG_compile_unit, children yes
        if (version >= 5) {
            // str_offsets/base attrs optional
        }
        b.uleb(DW_AT_stmt_list); b.uleb(if (version >= 5) DW_FORM_sec_offset else DW_FORM_data4)
        b.uleb(DW_AT_name); b.uleb(DW_FORM_string)
        b.uleb(DW_AT_comp_dir); b.uleb(DW_FORM_string)
        if (config.rangesOnRoot) {
            b.uleb(DW_AT_ranges); b.uleb(if (version >= 5) DW_FORM_sec_offset else DW_FORM_data4)
        }
        if (config.dwoName) {
            b.uleb(if (version >= 5) DW_AT_dwo_name else 0x2130); b.uleb(DW_FORM_string)
            b.uleb(0x2131); b.uleb(DW_FORM_data8)
            if (version < 5) { b.uleb(0x2133); b.uleb(DW_FORM_data4) }
        }
        b.uleb(0); b.uleb(0)

        // code 2: subprogram with low_pc/high_pc
        b.uleb(2); b.uleb(0x2e); b.u8(if (config.subprogramChildren) 1 else 0)
        b.uleb(DW_AT_name); b.uleb(DW_FORM_string)
        if (config.highPcForm == HighPcForm.ADDR) {
            b.uleb(DW_AT_low_pc); b.uleb(DW_FORM_addr)
            b.uleb(DW_AT_high_pc); b.uleb(DW_FORM_addr)
        } else if (config.highPcForm == HighPcForm.CONST) {
            b.uleb(DW_AT_low_pc); b.uleb(DW_FORM_addr)
            b.uleb(DW_AT_high_pc); b.uleb(DW_FORM_data4)
        } else if (config.highPcForm == HighPcForm.RANGES) {
            b.uleb(DW_AT_ranges); b.uleb(if (version >= 5) DW_FORM_sec_offset else DW_FORM_data4)
        } else if (config.highPcForm == HighPcForm.ZERO_CONST) {
            b.uleb(DW_AT_low_pc); b.uleb(DW_FORM_addr)
            b.uleb(DW_AT_high_pc); b.uleb(DW_FORM_data4)
        }
        if (config.abstractInline) {
            b.uleb(DW_AT_inline); b.uleb(DW_FORM_data1)
        }
        b.uleb(0); b.uleb(0)

        // code 3: inlined_subroutine
        if (config.includeInlined) {
            b.uleb(3); b.uleb(0x1d); b.u8(0)
            b.uleb(DW_AT_abstract_origin); b.uleb(DW_FORM_ref4)
            b.uleb(DW_AT_low_pc); b.uleb(DW_FORM_addr)
            b.uleb(DW_AT_high_pc); b.uleb(DW_FORM_data4)
            b.uleb(DW_AT_call_line); b.uleb(DW_FORM_data2)
            b.uleb(0); b.uleb(0)
        }

        // code 4: abstract subprogram root (DW_AT_inline, no PC) referenced by origin
        if (config.includeAbstractRoot) {
            b.uleb(4); b.uleb(0x2e); b.u8(0)
            b.uleb(DW_AT_name); b.uleb(DW_FORM_string)
            b.uleb(DW_AT_inline); b.uleb(DW_FORM_data1)
            b.uleb(0); b.uleb(0)
        }

        // code 5: subprogram with deliberately unknown form (for isolation test)
        if (config.unknownForm) {
            b.uleb(5); b.uleb(0x2e); b.u8(0)
            b.uleb(DW_AT_name); b.uleb(0x6e) // reserved form 0x6e
            b.uleb(0); b.uleb(0)
        }

        b.uleb(0) // end of set
        return b.build()
    }
}

enum class HighPcForm { CONST, ADDR, RANGES, ZERO_CONST }

data class AbbrevConfig(
    val highPcForm: HighPcForm = HighPcForm.CONST,
    val includeInlined: Boolean = false,
    val includeAbstractRoot: Boolean = false,
    val abstractInline: Boolean = false,
    val subprogramChildren: Boolean = false,
    val rangesOnRoot: Boolean = false,
    val dwoName: Boolean = false,
    val unknownForm: Boolean = false
)
