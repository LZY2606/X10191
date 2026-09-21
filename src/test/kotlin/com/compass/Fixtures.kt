package com.compass

import java.io.ByteArrayOutputStream

/**
 * Hand-built ELF64-LE objects with .debug_* sections. No system toolchain is
 * invoked, which lets tests pin exact behavior for special opcodes, multiple
 * sequences, overlapping/zero-length ranges, high_pc duality, relocation,
 * missing dwo, unknown forms and dangling references.
 */
class ElfBuilder {
    private class Sec(val name: String, val data: ByteArray, val alloc: Boolean)
    private val sections = mutableListOf<Sec>()
    private var baseVaddr = 0x400000L
    var machine = 62

    fun text(data: ByteArray, base: Long = 0x401000L): ElfBuilder {
        baseVaddr = base
        sections += Sec(".text", data, true); return this
    }
    fun debug(name: String, data: ByteArray): ElfBuilder { sections += Sec(name, data, false); return this }
    fun arbitrary(name: String, data: ByteArray): ElfBuilder { sections += Sec(name, data, false); return this }

    fun build(): ByteArray {
        val shstr = ByteArrayOutputStream().also { it.write(0) }
        val nameOff = HashMap<String, Int>()
        (sections.map { it.name } + ".shstrtab").distinct().forEach { nm ->
            nameOff[nm] = shstr.size(); shstr.write(nm.toByteArray()); shstr.write(0)
        }
        val nameTab = shstr.toByteArray()

        val ehSize = 64; val phSize = 56
        var off = ehSize + phSize
        val fileOff = HashMap<String, Long>()
        val secAddr = HashMap<String, Long>()
        var vaddr = baseVaddr
        for (s in sections) {
            off = (off + 7) and 7.inv().toInt()
            fileOff[s.name] = off.toLong()
            secAddr[s.name] = if (s.alloc) vaddr else 0L
            if (s.alloc) vaddr += s.data.size
            off += s.data.size
        }
        off = (off + 7) and 7.inv().toInt()
        fileOff[".shstrtab"] = off.toLong(); secAddr[".shstrtab"] = 0L; off += nameTab.size
        off = (off + 7) and 7.inv().toInt()
        val shOff = off.toLong()
        val allSecs = sections + Sec(".shstrtab", nameTab, false)
        val shNum = allSecs.size + 1

        val out = ByteArrayOutputStream()
        fun padTo(o: Int) { while (out.size() < o) out.write(0) }
        val eh = ByteArray(ehSize)
        eh[0]=0x7f; eh[1]='E'.code.toByte(); eh[2]='L'.code.toByte(); eh[3]='F'.code.toByte()
        eh[4]=2; eh[5]=1; eh[6]=1
        put16(eh,16,2); put16(eh,18,machine); put32(eh,20,1)
        put64(eh,32,ehSize.toLong()); put64(eh,40,shOff)
        put16(eh,52,ehSize); put16(eh,54,phSize); put16(eh,56,1)
        put16(eh,58,64); put16(eh,60,shNum); put16(eh,62,shNum-1)
        out.write(eh)
        val ph = ByteArray(phSize)
        put32(ph,0,1); put32(ph,4,5); put64(ph,8,0L)
        put64(ph,16,baseVaddr); put64(ph,24,baseVaddr)
        val textSec = sections.firstOrNull { it.alloc }
        val memsz = textSec?.data?.size?.toLong() ?: 0L
        put64(ph,32,memsz); put64(ph,40,memsz); put64(ph,48,0x1000L)
        padTo(ehSize); out.write(ph)
        for (s in sections) { padTo(fileOff[s.name]!!.toInt()); out.write(s.data) }
        padTo(fileOff[".shstrtab"]!!.toInt()); out.write(nameTab)

        padTo(shOff.toInt())
        fun writeSh(name: String?, type: Int, flags: Long, addr: Long, offset: Long, size: Long) {
            val h = ByteArray(64)
            if (name != null) put32(h,0,nameOff[name]!!.toLong())
            put32(h,4,type); put64(h,8,flags); put64(h,16,addr); put64(h,24,offset)
            put64(h,32,size); put64(h,48,1)
            out.write(h)
        }
        writeSh(null,0,0,0,0,0)
        for (s in allSecs) writeSh(s.name, 1, if (s.alloc) 0x6L else 0L, secAddr[s.name]!!,
            fileOff[s.name]!!, s.data.size.toLong())
        return out.toByteArray()
    }

    companion object {
        fun put16(a: ByteArray, o: Int, v: Int) { a[o]=(v and 0xff).toByte(); a[o+1]=((v shr 8) and 0xff).toByte() }
        fun put32(a: ByteArray, o: Int, v: Int) = put32(a, o, v.toLong())
        fun put32(a: ByteArray, o: Int, v: Long) { for (i in 0..3) a[o+i]=((v shr (i*8)) and 0xff).toByte() }
        fun put64(a: ByteArray, o: Int, v: Long) { for (i in 0..7) a[o+i]=((v shr (i*8)) and 0xff).toByte() }
    }
}

/** Little-endian writer for the synthetic debug sections. */
class Bin {
    private val out = ByteArrayOutputStream()
    val size get() = out.size()
    fun bytes(): ByteArray = out.toByteArray()
    fun u8(v: Int) = apply { out.write(v and 0xff) }
    fun u16(v: Int) = apply { out.write(v and 0xff); out.write((v shr 8) and 0xff) }
    fun u32(v: Long) = apply { for (i in 0..3) out.write(((v shr (i*8)) and 0xff).toInt()) }
    fun u64(v: Long) = apply { for (i in 0..7) out.write(((v shr (i*8)) and 0xff).toInt()) }
    fun raw(a: ByteArray) = apply { out.write(a) }
    fun cstr(s: String) = apply { out.write(s.toByteArray()); out.write(0) }
    fun uleb(v: Int) = uleb(v.toLong())
    fun uleb(v: Long) = apply {
        var x = v
        while (true) {
            var b = (x and 0x7f).toInt(); x = x ushr 7
            if (x != 0L) b = b or 0x80
            out.write(b); if (x == 0L) break
        }
    }
    fun sleb(v: Int) = sleb(v.toLong())
    fun sleb(v: Long) = apply {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt(); val sign = b and 0x40; x = x shr 6
            val done = (x == 0L && sign == 0) || (x == -1L && sign != 0)
            out.write(if (done) b else b or 0x80); if (done) break
        }
    }
    fun unitLen(content: ByteArray, dwarf64: Boolean = false): ByteArray =
        if (dwarf64) Bin().u32(0xffff_ffffL).u64(content.size.toLong()).raw(content).bytes()
        else Bin().u32(content.size.toLong()).raw(content).bytes()
}
