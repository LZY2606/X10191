package compass.elf

import compass.util.Cursor
import compass.util.ParseException
import java.io.ByteArrayOutputStream
import java.util.zip.Inflater

data class SectionHeader(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
    val compressed: Boolean = false,
    val nameOffset: Int = 0,
)

data class ProgramHeader(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    val isLoad get() = type == PT_LOAD
    companion object { const val PT_LOAD = 1 }
}

class ElfFile(val raw: ByteArray, val fileName: String = "<memory>") {
    val elfClass: Int       // 1 = 32-bit, 2 = 64-bit
    val dataEncoding: Int   // 1 = LE, 2 = BE
    val isLittleEndian: Boolean get() = dataEncoding == 1
    val version: Int
    val osabi: Int
    val type: Int
    val machine: Int
    val entry: Long
    val sections: List<SectionHeader>
    val programHeaders: List<ProgramHeader>
    val addressSizeBytes: Int get() = if (elfClass == 2) 8 else 4

    private val sectionByName: Map<String, SectionHeader>

    init {
        if (raw.size < 16 || raw[0] != 0x7f.toByte() || raw[1] != 'E'.code.toByte() ||
            raw[2] != 'L'.code.toByte() || raw[3] != 'F'.code.toByte()
        ) throw ParseException("not an ELF file: bad magic in $fileName")
        elfClass = raw[4].toInt() and 0xff
        dataEncoding = raw[5].toInt() and 0xff
        if (elfClass !in 1..2) throw ParseException("unsupported EI_CLASS=$elfClass")
        if (dataEncoding !in 1..2) throw ParseException("unsupported EI_DATA=$dataEncoding")
        if (dataEncoding == 2) throw ParseException("big-endian ELF is not supported")
        version = raw[6].toInt() and 0xff
        osabi = raw[7].toInt() and 0xff

        val c = Cursor(raw)
        if (elfClass == 2) {
            c.seek(16)
            type = c.u16(); machine = c.u16(); c.u32() // version
            entry = c.u64()
            val phoff = c.u64(); val shoff = c.u64()
            c.u32() // flags
            val ehsize = c.u16(); c.u16() /*phentsize*/; val phnum = c.u16()
            c.u16() /*shentsize*/; val shnum = c.u16(); val shstrndx = c.u16()
            programHeaders = parsePh64(c, phoff, phnum)
            sections = parseSh64(c, shoff, shnum, shstrndx)
        } else {
            c.seek(16)
            type = c.u16(); machine = c.u16(); c.u32()
            entry = c.u32()
            val phoff = c.u32(); val shoff = c.u32()
            c.u32()
            c.u16(); c.u16(); val phnum = c.u16()
            c.u16(); val shnum = c.u16(); val shstrndx = c.u16()
            programHeaders = parsePh32(c, phoff, phnum)
            sections = parseSh32(c, shoff, shnum, shstrndx)
        }
        sectionByName = sections.associateBy { it.name }
    }

    private fun parsePh64(c: Cursor, off: Long, num: Int): List<ProgramHeader> {
        val out = ArrayList<ProgramHeader>(num)
        for (i in 0 until num) {
            c.seek(off.ensureInt("phoff") + i * 56)
            val pt = c.u32().toInt(); val flags = c.u32().toInt()
            val poff = c.u64(); val va = c.u64(); val pa = c.u64()
            val fsz = c.u64(); val msz = c.u64(); val align = c.u64()
            out += ProgramHeader(pt, flags, poff, va, pa, fsz, msz, align)
        }
        return out
    }

    private fun parsePh32(c: Cursor, off: Long, num: Int): List<ProgramHeader> {
        val out = ArrayList<ProgramHeader>(num)
        for (i in 0 until num) {
            c.seek(off.ensureInt() + i * 32)
            val pt = c.u32().toInt(); val poff = c.u32(); val va = c.u32(); val pa = c.u32()
            val fsz = c.u32(); val msz = c.u32(); val flags = c.u32().toInt(); val align = c.u32()
            out += ProgramHeader(pt, flags, poff, va, pa, fsz, msz, align)
        }
        return out
    }

    private data class RawSh(
        val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long,
    )

    private fun parseSh64(c: Cursor, shoff: Long, num: Int, shstrndx: Int): List<SectionHeader> {
        val raws = ArrayList<RawSh>(num)
        for (i in 0 until num) {
            c.seek(shoff.ensureInt("shoff") + i * 64)
            val no = c.u32().toInt(); val st = c.u32().toInt(); val fl = c.u64()
            val ad = c.u64(); val of = c.u64(); val sz = c.u64()
            val lk = c.u32().toInt(); val inf = c.u32().toInt(); val al = c.u64(); val es = c.u64()
            raws += RawSh(no, st, fl, ad, of, sz, lk, inf, al, es)
        }
        return nameSections(raws, shstrndx)
    }

    private fun parseSh32(c: Cursor, shoff: Long, num: Int, shstrndx: Int): List<SectionHeader> {
        val raws = ArrayList<RawSh>(num)
        for (i in 0 until num) {
            c.seek(shoff.ensureInt() + i * 40)
            val no = c.u32().toInt(); val st = c.u32().toInt(); val fl = c.u32()
            val ad = c.u32(); val of = c.u32(); val sz = c.u32()
            val lk = c.u16(); val inf = c.u16(); val al = c.u32(); val es = c.u32()
            raws += RawSh(no, st, fl, ad, of, sz, lk, inf, al, es)
        }
        return nameSections(raws, shstrndx)
    }

    private fun nameSections(raws: List<RawSh>, shstrndx: Int): List<SectionHeader> {
        val strtab = if (shstrndx in raws.indices) sliceRaw(raws[shstrndx].offset, raws[shstrndx].size) else ByteArray(0)
        return raws.map { r ->
            val name = readElfString(strtab, r.nameOff)
            val compressed = name.startsWith(".zdebug") || isChdrCompressed(r)
            SectionHeader(name, r.type, r.flags, r.addr, r.offset, r.size, r.link, r.info, r.addralign, r.entsize,
                compressed = compressed, nameOffset = r.nameOff)
        }
    }

    /** SHF_COMPRESSED with ELFCOMPRESS_ZLIB. */
    private fun isChdrCompressed(r: RawSh): Boolean {
        if (r.flags and 0x800L == 0L || r.size < 4) return false
        return try {
            val c = Cursor(raw).seek(r.offset.ensureInt())
            if (elfClass == 2) c.u32().toInt() == 1 else c.u32().toInt() == 1
        } catch (_: Exception) { false }
    }

    fun section(name: String): SectionHeader? = sectionByName[name]

    /** Bytes for a section, transparently decompressing zlib / .zdebug. */
    fun sectionBytes(sh: SectionHeader): ByteArray {
        if (sh.name.startsWith(".zdebug")) {
            val b = sliceRaw(sh.offset, sh.size)
            if (b.size < 12 || String(b, 0, 8, Charsets.US_ASCII) != "ZLIB\0\0\0")
                throw ParseException("malformed .zdebug section ${sh.name}")
            return zlibInflate(b, 12)
        }
        if (isChdrByName(sh)) {
            val b = sliceRaw(sh.offset, sh.size)
            val chdrSize = if (elfClass == 2) 24 else 12
            return zlibInflate(b, chdrSize)
        }
        return sliceRaw(sh.offset, sh.size)
    }

    private fun isChdrByName(sh: SectionHeader): Boolean = sh.flags and 0x800L != 0L

    private fun sliceRaw(offset: Long, size: Long): ByteArray {
        val o = offset.ensureInt("section offset")
        val s = size.ensureInt("section size")
        if (o < 0 || s < 0 || o + s > raw.size)
            throw ParseException("section bytes out of file bounds: off=$o size=$s filesz=${raw.size}")
        return raw.copyOfRange(o, o + s)
    }

    /** Virtual address of the lowest PT_LOAD segment (preferred mapping base). */
    val preferredBase: Long by lazy {
        programHeaders.filter { it.isLoad && it.memsz > 0 }.minOfOrNull { it.vaddr } ?: 0L
    }

    fun containsFileOffset(off: Long): Boolean = programHeaders.any {
        it.isLoad && off >= it.offset && off < it.offset + it.filesz
    }

    fun vaddrToOffset(va: Long): Long? {
        for (p in programHeaders) {
            if (p.isLoad && va >= p.vaddr && va < p.vaddr + p.filesz) return p.offset + (va - p.vaddr)
        }
        return null
    }

    /** GNU Build-ID from PT_NOTE / SHT_NOTE (NT_GNU_BUILD_ID=3, name "GNU"). */
    val buildId: String? by lazy { readBuildId() }

    private fun readBuildId(): String? {
        // Section based notes first.
        for (sh in sections) {
            if (sh.type == SHT_NOTE) {
                try { parseNote(sectionBytes(sh))?.let { return it } } catch (_: Exception) { /* keep scanning */ }
            }
        }
        for (ph in programHeaders) {
            if (ph.type == PT_NOTE) {
                try { parseNote(sliceRaw(ph.offset, ph.filesz))?.let { return it } } catch (_: Exception) { }
            }
        }
        return null
    }

    private fun parseNote(buf: ByteArray): String? {
        val c = Cursor(buf)
        while (c.remaining > 12) {
            val namesz = c.u32().toInt(); val descsz = c.u32().toInt(); val type = c.u32().toInt()
            if (namesz <= 0 || namesz > 64 || descsz < 0 || descsz > 1024) return null
            val nameBytes = c.bytes(namesz)
            c.seek(align4(c.pos))
            val nameEnd = nameBytes.indexOf(0)
            val name = if (nameEnd >= 0) String(nameBytes, 0, nameEnd) else String(nameBytes)
            val desc = c.bytes(descsz)
            c.seek(align4(c.pos))
            if (type == 3 && name == "GNU") return desc.joinToString("") { "%02x".format(it) }
        }
        return null
    }

    companion object {
        const val SHT_NOTE = 7
        const val PT_NOTE = 4
        fun align4(x: Int) = (x + 3) and 3.inv()
        private fun zlibInflate(b: ByteArray, skip: Int): ByteArray {
            val inf = Inflater()
            inf.setInput(b, skip, b.size - skip)
            val out = ByteArrayOutputStream(b.size * 3 + 64)
            val tmp = ByteArray(8192)
            try {
                while (!inf.finished()) {
                    val n = inf.inflate(tmp)
                    if (n == 0) {
                        if (inf.needsInput() || inf.needsDictionary()) throw ParseException("truncated compressed section")
                        break
                    }
                    out.write(tmp, 0, n)
                }
            } catch (e: Exception) { throw ParseException("zlib inflate failed: ${e.message}") } finally { inf.end() }
            return out.toByteArray()
        }
        internal fun readElfString(tab: ByteArray, off: Int): String {
            if (off < 0 || off >= tab.size) return ""
            var end = off
            while (end < tab.size && tab[end] != 0.toByte()) end++
            return String(tab, off, end - off, Charsets.UTF_8)
        }
    }
}

internal fun Long.ensureInt(what: String = "offset"): Int {
    if (this < 0 || this > Int.MAX_VALUE.toLong()) throw ParseException("$what does not fit file: $this")
    return toInt()
}
