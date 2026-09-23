package compass.dwarf

import compass.core.ByteCursor
import compass.core.CursorException

object ElfParser {
    private const val SHT_NULL = 0
    private const val SHT_PROGBITS = 1
    private const val SHT_SYMTAB = 2
    private const val SHT_STRTAB = 3
    private const val SHT_NOBITS = 8
    private const val SHT_REL = 9
    private const val SHT_RELA = 4

    private const val ET_EXEC = 2
    private const val ET_DYN = 3

    private const val PT_LOAD = 1

    fun parse(bytes: ByteArray): ElfImage {
        val issues = mutableListOf<ParseIssue>()
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'B'.code.toByte() ||
            bytes[2] != 'I'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw CursorException("不是 ELF 文件（魔数不匹配）")
        }
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw CursorException("不支持的 ELF 类别: $elfClass")
        val dataEnc = bytes[5].toInt()
        val le = when (dataEnc) { 1 -> true; 2 -> false; else -> throw CursorException("未知 ELF 数据编码 $dataEnc") }
        val c = ByteCursor(bytes)
        c.pos = 16
        val elf64 = elfClass == 2
        fun u16(): Int = if (le) c.u16() else read16be(c)
        fun u32(): Long = if (le) c.u32() else read32be(c)
        fun u64(): Long = if (le) c.i64() else read64be(c)

        val machine = u16()
        val type = u16()
        c.pos = if (elf64) 0x18 else 0x18
        val entry = if (elf64) u64() else u32()
        val phoff = if (elf64) u64().also { c.pos = 0x20 } else u32().also { c.pos = 0x1c }
        val shoff = if (elf64) { c.pos = 0x28; u64() } else { c.pos = 0x20; u32() }
        c.pos = if (elf64) 0x36 else 0x2a
        val phentsize = u16()
        val phnum = u16()
        val shentsize = u16()
        val shnum = u16()
        val shstrndx = u16()

        // ---- section headers ----
        val rawSections = ArrayList<RawSh>(shnum)
        for (i in 0 until shnum) {
            val p = (shoff + i.toLong() * shentsize).toInt()
            if (p < 0 || p + shentsize > bytes.size) {
                issues += ParseIssue(ParseIssue.Severity.ERROR, "elf.section.overflow", "section header #$i 越界", "ELF", p.toLong())
                break
            }
            c.pos = p
            val sh = if (elf64) {
                val n = u32(); val t = u32(); val fl = u64(); val a = u64(); val o = u64(); val sz = u64()
                val lk = u32().toInt(); val inf = u32().toLong(); RawSh(n, t, fl, a, o, sz, lk, inf, u64(), u64())
            } else {
                val n = u32(); val t = u32(); val fl = u32(); val a = u32(); val o = u32(); val sz = u32()
                val lk = u32().toInt(); val inf = u32(); RawSh(n, t, fl, a, o, sz, lk, inf, u32(), u32())
            }
            rawSections += sh
        }
        val shstr = rawSections.getOrNull(shstrndx)
        fun nameAt(off: Long): String {
            if (shstr == null || shstr.type.toInt() == SHT_NOBITS) return ""
            return try {
                val sc = ByteCursor(bytes, shstr.off.toInt(), shstr.size.toInt())
                sc.readCStringAt(off)
            } catch (e: CursorException) { "" }
        }

        // ---- program headers (segments) ----
        val segments = ArrayList<SegmentInfo>(phnum)
        for (i in 0 until phnum) {
            val p = (phoff + i.toLong() * phentsize).toInt()
            if (p < 0 || p + phentsize > bytes.size) {
                issues += ParseIssue(ParseIssue.Severity.ERROR, "elf.phdr.overflow", "program header #$i 越界", "ELF", p.toLong())
                break
            }
            c.pos = p
            if (elf64) {
                val pt = u32(); val fl = u32(); val off = u64(); val va = u64(); c.pos += 8; val fsz = u64(); val msz = u64()
                segments += SegmentInfo(pt, off, va, fsz, msz, fl)
            } else {
                val pt = u32(); val off = u32(); val va = u32(); c.pos += 4; val fsz = u32(); val msz = u32(); val fl = u32()
                segments += SegmentInfo(pt, off, va, fsz, msz, fl)
            }
        }

        val sections = ArrayList<SectionInfo>()
        val sectionBytes = HashMap<String, ByteArray>()
        for ((i, sh) in rawSections.withIndex()) {
            val nm = nameAt(sh.nameOff)
            val summary = if (sh.type != SHT_NOBITS.toLong() && sh.size > 0) {
                try { ByteSummary.of(bytes.copyOfRange(sh.off.toInt(), (sh.off + sh.size).toInt())) }
                catch (e: Exception) { issues += ParseIssue(ParseIssue.Severity.ERROR, "elf.section.bytes", "section $nm 字节越界", nm, sh.off); null }
            } else null
            sections += SectionInfo(nm, sh.off, sh.addr, sh.size, sh.link, sh.info.toInt(), sh.entsize, summary)
            if (sh.type != SHT_NOBITS.toLong() && sh.size > 0 && nm.isNotEmpty()) {
                if (sh.off < 0 || sh.off + sh.size > bytes.size) {
                    issues += ParseIssue(ParseIssue.Severity.ERROR, "elf.section.overflow", "section $nm 数据越界", nm, sh.off)
                } else {
                    sectionBytes[nm] = bytes.copyOfRange(sh.off.toInt(), (sh.off + sh.size).toInt())
                }
            }
        }

        // ---- relocations ----
        val relocs = HashMap<String, List<Relocation>>()
        val symTables = HashMap<Int, LongArray>()
        for ((i, sh) in rawSections.withIndex()) {
            val nm = nameAt(sh.nameOff)
            if (sh.type.toInt() != SHT_REL && sh.type.toInt() != SHT_RELA) continue
            val symSh = rawSections.getOrNull(sh.link) ?: continue
            val symVals = symTables.getOrPut(sh.link) { buildSymValues(bytes, symSh, elf64, le) }
            val rela = sh.type.toInt() == SHT_RELA
            val entsize = if (sh.entsize != 0L) sh.entsize else (if (elf64) (if (rela) 24L else 16L) else (if (rela) 12L else 8L))
            val count = if (entsize > 0) (sh.size / entsize).toInt() else 0
            val list = ArrayList<Relocation>()
            for (j in 0 until count) {
                c.pos = (sh.off + j * entsize).toInt()
                try {
                    val rOffset = if (elf64) c.i64() else c.u32()
                    val info = if (elf64) c.i64() else c.u32()
                    val addend = when {
                        rela && elf64 -> c.i64()
                        rela -> c.i32().toLong()
                        else -> 0L
                    }
                    val sym = if (elf64) info.ushr(32) else info.ushr(8)
                    val rtype = if (elf64) info and 0xffffffff else info and 0xff
                    list += Relocation(rOffset, classify(machine, rtype), addend, symVals.getOrElse(sym.toInt()) { 0L }, rtype)
                } catch (e: CursorException) {
                    issues += ParseIssue(ParseIssue.Severity.ERROR, "elf.reloc.truncated", "$nm 重定位 #$j 截断", nm)
                    break
                }
            }
            val targetName = nameAt(rawSections[sh.link].nameOff)
            // sh_info 指向应用目标 section（对 RELA/REL 通常如此）
            val appliedTo = rawSections.getOrNull(sh.info.toInt())?.let { nameAt(it.nameOff) }
                ?: nm.removePrefix(".rela").removePrefix(".rel")
            relocs.merge(appliedTo, list) { a, b -> a + b }
        }

        return ElfImage(
            elfClass, le, machine, type == ET_DYN, entry,
            sections, segments.filter { it.type == PT_LOAD }, relocs, sectionBytes, issues
        )
    }

    private fun buildSymValues(bytes: ByteArray, symSh: RawSh, elf64: Boolean, le: Boolean): LongArray {
        if (symSh.type.toInt() != SHT_SYMTAB && symSh.type.toInt() != 11 /*SHT_DYNSYM*/) return LongArray(0)
        val entsize = if (symSh.entsize != 0L) symSh.entsize else (if (elf64) 24L else 16L)
        val n = (symSh.size / entsize).toInt()
        val vals = LongArray(n)
        if (symSh.off + symSh.size > bytes.size) return vals
        for (j in 0 until n) {
            val c = ByteCursor(bytes, (symSh.off + j * entsize).toInt(), entsize.toInt())
            vals[j] = if (elf64) { c.pos = 8; if (le) c.i64() else read64be(c) }
            else { if (le) c.u32() else read32be(c) }
        }
        return vals
    }

    private fun classify(machine: Int, type: Long): RelocKind = when (machine) {
        0x3e -> when (type) { // x86-64
            8L -> RelocKind.RELATIVE // R_X86_64_RELATIVE
            1L, 2L -> RelocKind.ABSOLUTE
            else -> RelocKind.UNKNOWN
        }
        0xb7 -> when (type) { // aarch64
            1027L -> RelocKind.RELATIVE // R_AARCH64_RELATIVE
            257L, 1025L -> RelocKind.ABSOLUTE
            else -> RelocKind.UNKNOWN
        }
        0x03 -> when (type) { // x86
            8L -> RelocKind.RELATIVE
            1L -> RelocKind.ABSOLUTE
            else -> RelocKind.UNKNOWN
        }
        else -> RelocKind.UNKNOWN
    }

    private fun read16be(c: ByteCursor): Int { c.require(2); val b = c.data; val p = c.base + c.pos; c.pos += 2
        return ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF) }
    private fun read32be(c: ByteCursor): Long { c.require(4); val b = c.data; val p = c.base + c.pos; c.pos += 4
        var v = 0L; for (i in 0 until 4) v = (v shl 8) or (b[p + i].toLong() and 0xFF); return v }
    private fun read64be(c: ByteCursor): Long { c.require(4); var v = 0L; repeat(2) { v = (v shl 32) or read32be(c) }; return v }

    private data class RawSh(val nameOff: Long, val type: Long, val flags: Long, val addr: Long, val off: Long, val size: Long, val link: Int, val info: Long, val addralign: Long, val entsize: Long)
}
