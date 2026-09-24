package compass.dwarf

import compass.elf.ElfModel
import compass.elf.ElfSection

/** 一组已读取（且必要时已打重定位补丁）的 DWARF section 字节 */
class SectionSet(private val map: Map<String, ByteArray>) {
    operator fun get(name: String): ByteArray? = map[name]
    fun require(name: String): ByteArray = map[name] ?: throw ParseException("缺少 section $name")
    val names: Set<String> get() = map.keys

    companion object {
        // x86_64
        const val R_X86_64_32 = 10
        const val R_X86_64_64 = 1
        const val R_X86_64_PC32 = 2
        // AArch64
        const val R_AARCH64_ABS32 = 258
        const val R_AARCH64_ABS64 = 257
        const val R_AARCH64_PREL32 = 261

        private val DEBUG_SECTIONS = listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str", ".debug_str",
            ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists",
            ".debug_loc", ".debug_loclists",
        )

        /** 从 ELF 抽取 DWARF section；对可重定位目标文件，把 REL(A) 重定位作用到副本上。 */
        fun fromElf(elf: ElfModel, warnings: MutableList<String> = mutableListOf()): SectionSet {
            val out = linkedMapOf<String, ByteArray>()
            for (name in DEBUG_SECTIONS) {
                elf.section(name)?.let { out[name] = it.slice(elf.bytes) }
            }
            // 拆分 DWARF：.debug_info.dwo 等
            for (s in elf.sections) {
                if (s.name.endsWith(".dwo") && s.size > 0 && !out.containsKey(s.name)) {
                    out[s.name] = s.slice(elf.bytes)
                }
            }
            applyRelocations(elf, out, warnings)
            return SectionSet(out)
        }

        private fun applyRelocations(elf: ElfModel, sections: MutableMap<String, ByteArray>, warnings: MutableList<String>) {
            if (elf.type != ElfModel.ET_REL) return
            val rela = elf.segments // no-op to keep imports tidy
            val relocSecs = elf.sections.filter { it.type == ElfModel.SHT_RELA || it.type == ElfModel.SHT_REL }
            for (relSec in relocSecs) {
                val target = elf.sections.getOrNull(relSec.info) ?: continue
                val targetName = target.name
                val buf = sections[targetName] ?: continue
                val is64 = elf.elfClass == 2
                val isRela = relSec.type == ElfModel.SHT_RELA
                val ent = if (relSec.entsize != 0L) relSec.entsize else (if (isRela) (if (is64) 24 else 12) else (if (is64) 16 else 8))
                val count = (relSec.size / ent).toInt()
                val r = compass.dwarf.BinReader(elf.bytes, relSec.offset.toInt(), elf.endian == 1)
                val linkSec = elf.sections.getOrNull(relSec.link)
                for (i in 0 until count) {
                    val base = relSec.offset.toInt() + i * ent.toInt()
                    r.seek(base)
                    val rOffset = if (is64) r.u64() else r.u32()
                    val rInfo = if (is64) r.u64() else r.u32()
                    val symIdx = if (is64) (rInfo ushr 32).toInt() else ((rInfo ushr 8).toInt() and 0xff)
                    val rType = if (is64) (rInfo and 0xffffffffL).toInt() else (rInfo and 0xffL).toInt()
                    val addend = if (isRela) { if (is64) r.u64() else r.u32() } else 0L
                    val sym = if (linkSec != null) elf.symbols[linkSec.index * 1_000_000 + symIdx] else null
                    val symValue = sym?.value ?: 0L
                    when {
                        elf.machine == ElfModel.MACHINE_X86_64 && rType == R_X86_64_64 ->
                            patch(buf, rOffset.toInt(), 8, symValue + addend, elf.endian == 1, warnings, relSec)
                        elf.machine == ElfModel.MACHINE_X86_64 && rType == R_X86_64_32 ->
                            patch(buf, rOffset.toInt(), 4, symValue + addend, elf.endian == 1, warnings, relSec)
                        elf.machine == ElfModel.MACHINE_X86_64 && rType == R_X86_64_PC32 ->
                            patch(buf, rOffset.toInt(), 4, symValue + addend - (target.addr + rOffset), elf.endian == 1, warnings, relSec)
                        elf.machine == ElfModel.MACHINE_AARCH64 && rType == R_AARCH64_ABS64 ->
                            patch(buf, rOffset.toInt(), 8, symValue + addend, elf.endian == 1, warnings, relSec)
                        elf.machine == ElfModel.MACHINE_AARCH64 && rType == R_AARCH64_ABS32 ->
                            patch(buf, rOffset.toInt(), 4, symValue + addend, elf.endian == 1, warnings, relSec)
                        elf.machine == ElfModel.MACHINE_AARCH64 && rType == R_AARCH64_PREL32 ->
                            patch(buf, rOffset.toInt(), 4, symValue + addend - (target.addr + rOffset), elf.endian == 1, warnings, relSec)
                    }
                }
            }
        }

        private fun patch(buf: ByteArray, at: Int, width: Int, value: Long, le: Boolean,
                          warnings: MutableList<String>, relSec: ElfSection) {
            if (at < 0 || at + width > buf.size) {
                warnings.add("重定位补丁越过 section 边界 (${relSec.name} +0x${at.toString(16)})，已跳过")
                return
            }
            BinReader(buf, at, le).putWord(at, width, value)
        }
    }
}
