package com.luopan.elf

import com.luopan.dwarf.Binary
import com.luopan.dwarf.DwarfReadException
import com.luopan.dwarf.Endian

/**
 * 对可重定位目标文件（.o / .dwo 骨架）应用调试 section 重定位。
 * 仅处理解析 DWARF 所需的绝对地址类重定位；未知类型登记诊断，不静默篡改字节。
 */
class RelocationResult(
    val sections: Map<String, ByteArray>,
    val appliedCount: Int,
    val diagnostics: List<String>,
)

object RelocationApplier {
    private const val SHT_SYMTAB = 2
    private const val SHT_RELA = 4
    private const val SHT_REL = 9

    fun apply(image: ElfImage): RelocationResult {
        val out = LinkedHashMap<String, ByteArray>()
        image.sections.forEach { if (it.type != 8) out[it.name] = it.bytes.copyOf() }
        val diag = mutableListOf<String>()
        var applied = 0
        if (!image.isRelocatable) return RelocationResult(out, 0, emptyList())

        val symtabs = image.sections.filter { it.type == SHT_SYMTAB }
        val symbolsByLink = symtabs.associate { it.link to readSymbols(image, it) }

        for (rel in image.sections.filter { it.type == SHT_RELA || it.type == SHT_REL }) {
            val targetName = image.sections.getOrNull(rel.info)?.name ?: continue
            val target = out[targetName] ?: continue
            val syms = symbolsByLink[rel.link]
            if (syms == null) {
                diag.add("relocation ${rel.name}: symbol table ${rel.link} missing")
                continue
            }
            val isRela = rel.type == SHT_RELA
            val esize = if (isRela) when (image.elfClass) { 1 -> 12; else -> 24 }
                        else when (image.elfClass) { 1 -> 8; else -> 16 }
            if (rel.entsize.toInt() !in listOf(0, esize)) {
                diag.add("relocation ${rel.name}: unexpected entsize ${rel.entsize}")
            }
            val count = if (esize == 0) 0 else rel.bytes.size / esize
            val rb = Binary(rel.bytes, 0, rel.bytes.size, image.endian)
            for (i in 0 until count) {
                val off: Long; val symIdx: Int; val type: Int; val addend: Long
                if (image.elfClass == 2) {
                    off = rb.u8(); val info = rb.u8()
                    symIdx = (info ushr 32).toInt(); type = info.toInt() and 0xffffffff.toInt()
                    addend = if (isRela) rb.sleb64() else 0L
                } else {
                    off = rb.u4().toLong() and 0xffffffffL
                    val info = rb.u4()
                    symIdx = info ushr 8; type = info and 0xff
                    addend = if (isRela) rb.s4().toLong() else 0L
                }
                val sym = syms.getOrNull(symIdx)
                val symValue = sym?.value ?: 0L
                val width = relocWidth(image.machine, type)
                if (width == 0) {
                    diag.add("relocation ${rel.name}: unsupported reloc type $type (machine ${image.machine}) skipped")
                    continue
                }
                val existing = readTarget(target, off, width, image.endian)
                val base = if (isRela) 0L else existing
                val value = (symValue + addend + base) and mask(width)
                if (!writeTarget(target, off, value, width, image.endian)) {
                    diag.add("relocation ${rel.name}: write out of bounds at off=$off width=$width")
                    continue
                }
                applied++
            }
        }
        return RelocationResult(out, applied, diag)
    }

    private fun Binary.sleb64(): Long = u8()

    private fun relocWidth(machine: Int, type: Int): Int = when (machine) {
        62 -> when (type) { // EM_X86_64
            1 -> 8  // R_X86_64_64
            2, 3, 4, 9, 10, 11, 24, 38, 39, 40, 41, 42, 43 -> 4
            else -> 0
        }
        3 -> when (type) { // EM_386
            1, 6, 7, 9, 10, 11, 17, 20, 21, 41, 42, 43 -> 4
            else -> 0
        }
        183 -> when (type) { // EM_AARCH64
            257, 258, 259, 261, 262, 263, 275, 1024, 1025, 1026, 1027 -> 8
            2, 260, 271, 272, 273, 274, 286, 287 -> 4
            else -> 0
        }
        else -> 0
    }

    private fun mask(width: Int): Long = if (width == 8) -1L else (1L shl (width * 8)) - 1

    private fun readTarget(t: ByteArray, off: Long, width: Int, endian: Endian): Long {
        val o = off.toInt()
        if (o < 0 || o + width > t.size) return 0L
        val b = Binary(t, o, width, endian)
        return b.uint(width)
    }

    private fun writeTarget(t: ByteArray, off: Long, value: Long, width: Int, endian: Endian): Boolean {
        val o = off.toInt()
        if (o < 0 || o + width > t.size) return false
        var v = value
        if (endian == Endian.LITTLE) {
            for (i in 0 until width) { t[o + i] = (v and 0xff).toByte(); v = v ushr 8 }
        } else {
            for (i in width - 1 downTo 0) { t[o + i] = (v and 0xff).toByte(); v = v ushr 8 }
        }
        return true
    }

    class Sym(val name: String, val value: Long, val shndx: Int)

    private fun readSymbols(image: ElfImage, symtab: ElfSection): List<Sym> {
        val es = if (symtab.entsize > 0) symtab.entsize.toInt()
                 else if (image.elfClass == 2) 24 else 16
        val strtab = image.sections.getOrNull(symtab.link)?.bytes ?: ByteArray(0)
        val count = symtab.bytes.size / es
        val b = Binary(symtab.bytes, 0, symtab.bytes.size, image.endian)
        val out = ArrayList<Sym>(count)
        for (i in 0 until count) {
            val nameOff: Int; val value: Long; val shndx: Int
            if (image.elfClass == 2) {
                nameOff = b.u4(); b.u1(); b.u1(); b.u2()
                value = b.u8(); b.u8()
                shndx = b.u2()
            } else {
                nameOff = b.u4(); value = b.u4().toLong() and 0xffffffffL
                b.u4(); b.u1(); b.u1(); shndx = b.u2()
            }
            val name = if (nameOff < strtab.size) cstr(strtab, nameOff) else ""
            out.add(Sym(name, value, shndx))
        }
        return out
    }

    private fun cstr(t: ByteArray, off: Int): String {
        var e = off
        while (e < t.size && t[e] != 0.toByte()) e++
        return String(t, off, e - off, Charsets.UTF_8)
    }
}
