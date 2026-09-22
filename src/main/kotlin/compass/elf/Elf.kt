package compass.elf

import compass.dwarf.DwarfException
import compass.dwarf.Reader
import java.security.MessageDigest

class ElfException(message: String) : Exception(message)

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray,
) {
    val sha256: String by lazy { sha256Hex(data) }
}

data class ProgramHeader(
    val type: Long,
    val flags: Long,
    val vaddr: Long,
    val offset: Long,
    val filesz: Long,
    val memsz: Long,
)

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val sections: List<ElfSection>,
    val programHeaders: List<ProgramHeader>,
    val fileSize: Long,
    val fileSha256: String,
) {
    private val byName = sections.associateBy { it.name }
    fun section(name: String): ElfSection? = byName[name]

    /** Lowest p_vaddr of PT_LOAD segments, useful when reasoning about load bias. */
    val minLoadVaddr: Long? = programHeaders.filter { it.type == 1L }.minOfOrNull { it.vaddr }

    companion object {
        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16) throw ElfException("file too small for ELF header")
            if (bytes[0].toInt() != 0x7F || bytes[1] != 'E'.code.toByte() ||
                bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) throw ElfException("not an ELF file (bad magic)")
            val elfClass = bytes[4].toInt()
            val is64 = when (elfClass) {
                1 -> false; 2 -> true
                else -> throw ElfException("unknown ELF class $elfClass")
            }
            val littleEndian = when (bytes[5].toInt()) {
                1 -> true; 2 -> false
                else -> throw ElfException("unknown ELF data encoding ${bytes[5]}")
            }
            val r = Reader(bytes, 0, bytes.size, littleEndian)
            try {
                r.pos = 16
                r.u16() // e_type
                r.u16() // e_machine
                r.u32() // e_version
                if (is64) {
                    r.u64() // e_entry
                    val phoff = r.u64()
                    val shoff = r.u64()
                    r.u32(); r.u16() // flags, ehsize
                    val phentsize = r.u16()
                    val phnum = r.u16()
                    val shentsize = r.u16()
                    val shnum = r.u16()
                    val shstrndx = r.u16()
                    return finish(bytes, is64, littleEndian, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
                } else {
                    r.u32() // e_entry
                    val phoff = r.u32()
                    val shoff = r.u32()
                    r.u32(); r.u16()
                    val phentsize = r.u16()
                    val phnum = r.u16()
                    val shentsize = r.u16()
                    val shnum = r.u16()
                    val shstrndx = r.u16()
                    return finish(bytes, is64, littleEndian, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
                }
            } catch (e: DwarfException) {
                throw ElfException("truncated ELF: ${e.message}")
            }
        }

        private fun finish(
            bytes: ByteArray, is64: Boolean, littleEndian: Boolean,
            phoff: Long, shoff: Long, phentsize: Int, phnum: Int,
            shentsize: Int, shnum: Int, shstrndx: Int,
        ): ElfFile {
            val r = Reader(bytes, 0, bytes.size, littleEndian)
            val phdrs = ArrayList<ProgramHeader>()
            if (phoff > 0 && phnum > 0) {
                if (phnum > 4096) throw ElfException("unreasonable program header count $phnum")
                for (i in 0 until phnum) {
                    val off = phoff + i.toLong() * phentsize
                    if (off < 0 || off >= bytes.size) throw ElfException("program header $i out of bounds")
                    r.pos = off.toInt()
                    if (is64) {
                        val type = r.u32(); val flags = r.u32()
                        val off2 = r.u64(); val vaddr = r.u64(); r.u64()
                        val filesz = r.u64(); val memsz = r.u64(); r.u64()
                        phdrs.add(ProgramHeader(type, flags, vaddr, off2, filesz, memsz))
                    } else {
                        val type = r.u32(); val off2 = r.u32(); val vaddr = r.u32(); r.u32()
                        val filesz = r.u32(); val memsz = r.u32(); val flags = r.u32()
                        phdrs.add(ProgramHeader(type, flags, vaddr, off2, filesz, memsz))
                    }
                }
            }
            if (shoff == 0L || shnum == 0) {
                return ElfFile(is64, littleEndian, emptyList(), phdrs, bytes.size.toLong(), sha256Hex(bytes))
            }
            if (shnum > 65535) throw ElfException("unreasonable section count $shnum")
            data class Shdr(val nameOff: Long, val type: Long, val addr: Long, val offset: Long, val size: Long)
            val shdrs = ArrayList<Shdr>()
            for (i in 0 until shnum) {
                val off = shoff + i.toLong() * shentsize
                if (off < 0 || off >= bytes.size) throw ElfException("section header $i out of bounds")
                r.pos = off.toInt()
                if (is64) {
                    val nameOff = r.u32(); val type = r.u32(); r.u64()
                    val addr = r.u64(); val secOff = r.u64(); val size = r.u64()
                    shdrs.add(Shdr(nameOff, type, addr, secOff, size))
                } else {
                    val nameOff = r.u32(); val type = r.u32(); r.u32()
                    val addr = r.u32(); val secOff = r.u32(); val size = r.u32()
                    shdrs.add(Shdr(nameOff, type, addr, secOff, size))
                }
            }
            val strSec = if (shstrndx in shdrs.indices) shdrs[shstrndx] else null
            val sections = ArrayList<ElfSection>()
            for (s in shdrs) {
                val name = if (strSec != null && s.nameOff != 0L) {
                    readStr(bytes, strSec.offset + s.nameOff) ?: ""
                } else ""
                val data = if (s.type == 8L || s.size == 0L) { // SHT_NOBITS
                    ByteArray(0)
                } else {
                    if (s.offset < 0 || s.size < 0 || s.offset + s.size > bytes.size) {
                        throw ElfException("section '$name' data out of bounds")
                    }
                    bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
                }
                sections.add(ElfSection(name, s.type, s.addr, s.offset, s.size, data))
            }
            return ElfFile(is64, littleEndian, sections, phdrs, bytes.size.toLong(), sha256Hex(bytes))
        }

        private fun readStr(bytes: ByteArray, offset: Long): String? {
            if (offset < 0 || offset >= bytes.size) return null
            var end = offset.toInt()
            while (end < bytes.size && bytes[end].toInt() != 0) end++
            return String(bytes, offset.toInt(), end - offset.toInt(), Charsets.UTF_8)
        }
    }
}
