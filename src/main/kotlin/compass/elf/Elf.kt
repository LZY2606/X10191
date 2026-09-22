package compass.elf

import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long
)

data class ElfFile(
    val elfClass: Int,
    val endian: java.nio.ByteOrder,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val sha256: String,
    val size: Long,
    private val raw: ByteArray
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(s: ElfSection): ByteArray {
        if (s.offset < 0 || s.offset + s.size > raw.size.toLong()) {
            throw BinaryParseException("section ${s.name} 字节范围越界")
        }
        return raw.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    fun sectionBytes(name: String): ByteArray? = section(name)?.let { sectionBytes(it) }
}

object ElfParser {
    private const val SHT_NOBITS = 8L

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 64 || bytes[0] != 0x7f.toByte() ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw BinaryParseException("不是 ELF 文件（魔数不匹配）")
        }
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw BinaryParseException("不支持的 ELF 类别 $elfClass")
        val endian = when (bytes[5].toInt()) {
            1 -> java.nio.ByteOrder.LITTLE_ENDIAN
            2 -> java.nio.ByteOrder.BIG_ENDIAN
            else -> throw BinaryParseException("不支持的 ELF 端序")
        }
        val r = Reader(bytes, endian)
        r.seek(16)
        val machine: Int
        val entry: Long
        val shoff: Long
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        if (elfClass == 2) {
            r.u2() // e_type
            machine = r.u2()
            r.u4() // e_version
            entry = r.u8()
            r.u8() // phoff
            shoff = r.u8()
            r.u4(); r.u4() // e_flags, e_ehsize
            r.u2(); r.u2() // phentsize, phnum
            shentsize = r.u2()
            shnum = r.u2()
            shstrndx = r.u2()
        } else {
            r.u2()
            machine = r.u2()
            r.u4()
            entry = r.u4long()
            r.u4() // phoff
            shoff = r.u4long()
            r.u4(); r.u4()
            r.u2(); r.u2()
            shentsize = r.u2()
            shnum = r.u2()
            shstrndx = r.u2()
        }
        if (shnum == 0 || shoff == 0L) throw BinaryParseException("ELF 无 section 头表")
        if (shoff > bytes.size.toLong()) throw BinaryParseException("e_shoff 越界")

        val raw = Array(shnum) { LongArray(8) }
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * shentsize).toInt())
            if (elfClass == 2) {
                raw[i][0] = r.u4long() // name offset
                raw[i][1] = r.u4long() // type
                raw[i][2] = r.u8()     // flags
                raw[i][3] = r.u8()     // addr
                raw[i][4] = r.u8()     // offset
                raw[i][5] = r.u8()     // size
                raw[i][6] = r.u4long() // link
                raw[i][7] = r.u4long() // info
                r.u8() // addralign
                r.u8() // entsize
            } else {
                raw[i][0] = r.u4long()
                raw[i][1] = r.u4long()
                raw[i][2] = r.u4long()
                raw[i][3] = r.u4long()
                raw[i][4] = r.u4long()
                raw[i][5] = r.u4long()
                raw[i][6] = r.u4long()
                raw[i][7] = r.u4long()
            }
        }

        val names = if (shstrndx in 0 until shnum) {
            val sh = raw[shstrndx]
            val off = sh[4].toInt(); val size = sh[5].toInt()
            if (off < 0 || off + size > bytes.size || size <= 0) ByteArray(0)
            else bytes.copyOfRange(off, off + size)
        } else ByteArray(0)

        fun shName(idx: Int): String {
            val no = raw[idx][0].toInt()
            if (names.isEmpty() || no < 0 || no >= names.size) return ""
            var end = no
            while (end < names.size && names[end].toInt() != 0) end++
            return if (end <= no) "" else String(names, no, end - no, Charsets.UTF_8)
        }

        val sections = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val a = raw[i]
            sections.add(
                ElfSection(
                    name = shName(i),
                    type = a[1].toInt(),
                    flags = a[2],
                    addr = a[3],
                    offset = a[4],
                    size = a[5],
                    link = a[6].toInt(),
                    info = a[7].toInt(),
                    addralign = 0L
                )
            )
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        return ElfFile(elfClass, endian, machine, entry, sections, digest, bytes.size.toLong(), bytes)
    }
}
