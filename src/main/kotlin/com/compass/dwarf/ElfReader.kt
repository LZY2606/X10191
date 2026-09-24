package com.compass.dwarf

import java.security.MessageDigest

class ElfReader(private val bytes: ByteArray) {
    private var little = true
    fun parse(): ElfSummary {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1].toInt() and 0xff != 69 || bytes[2].toInt() and 0xff != 0x4c || bytes[3].toInt() and 0xff != 0x46) {
            throw DwarfParseException("Not an ELF file")
        }
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw DwarfParseException("Unsupported ELF class")
        val dataEncoding = bytes[5].toInt()
        val little = dataEncoding == 1
        this.little = little
        val c = BinaryCursor(bytes, littleEndian = little)
        c.localSeek(16)
        val type = c.u16()
        val machine = c.u16()
        val version = c.u32()
        if (version.toInt() != 1) throw DwarfParseException("Unsupported ELF version")
        val entry = if (elfClass == 2) c.u64() else c.u32()
        if (elfClass == 2) { c.u64(); c.u64() } else { c.u32(); c.u32() }
        c.u32(); c.u16(); c.u16()
        val sectionHeaderOffset = if (elfClass == 2) c.u64() else c.u32()
        c.u32()
        val sectionHeaderEntrySize = c.u16()
        val sectionCount = c.u16()
        val sectionNameIndex = c.u16()
        if (sectionCount == 0 || sectionHeaderOffset == 0L) {
            return ElfSummary(elfClass, little, type, machine, entry, programBase = null)
        }
        val rawSections = (0 until sectionCount).map { index ->
            val off = sectionHeaderOffset + index.toLong() * sectionHeaderEntrySize
            c.localSeek(off.toInt())
            if (elfClass == 2) readSection64(c) else readSection32(c)
        }
        val namesRaw = rawSections.getOrNull(sectionNameIndex)
        val names = namesRaw?.let { sectionBytesPublic(it) }
        val named = rawSections.mapIndexed { index, raw ->
            val name = if (names != null && raw.nameOffset in 0 until names.size) {
                val end = (raw.nameOffset until names.size).firstOrNull { names[it].toInt() == 0 } ?: names.size
                String(names, raw.nameOffset, end - raw.nameOffset, Charsets.UTF_8)
            } else ""
            val digest = runCatching {
                val payload = sectionBytesPublic(raw)
                MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
            }.getOrElse { "error:${it.message}" }
            ElfSection(name, raw.type, raw.flags, raw.offset, raw.size, raw.virtualAddress, raw.link, raw.info, raw.alignment, raw.entrySize, digest)
        }
        return ElfSummary(elfClass, little, type, machine, entry, readBuildId(c, named, rawSections), named.filter { it.type == 1 }.minOfOrNull { it.virtualAddress }, named)
    }

    private data class RawSection(
        val nameOffset: Int, val type: Int, val flags: Long, val virtualAddress: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val alignment: Long, val entrySize: Long
    )

    private fun readSection32(c: BinaryCursor): RawSection {
        val name = c.u16(); val type = c.u32().toInt(); val flags = c.u32(); val va = c.u32()
        val off = c.u32(); val size = c.u32(); val link = c.u32().toInt(); val info = c.u32().toInt()
        val align = c.u32(); val ent = c.u32()
        return RawSection(nameOffset = name, type = type, flags = flags, virtualAddress = va, offset = off, size = size, link = link.toInt(), info = info.toInt(), alignment = align, entrySize = ent)
    }

    private fun readSection64(c: BinaryCursor): RawSection {
        val name = c.u16(); val type = c.u16(); val flags = c.u64(); val va = c.u64()
        val off = c.u64(); val size = c.u64(); val link = c.u32(); val info = c.u32()
        val align = c.u64(); val ent = c.u64()
        return RawSection(nameOffset = name, type = type, flags = flags, virtualAddress = va, offset = off, size = size, link = link.toInt(), info = info.toInt(), alignment = align, entrySize = ent)
    }

    private fun sectionBytesPublic(section: RawSection): ByteArray {
        val end = section.offset + section.size
        if (section.offset < 0 || section.size < 0 || end > bytes.size) throw DwarfParseException("ELF section out of bounds")
        return bytes.copyOfRange(section.offset.toInt(), end.toInt())
    }

    fun sectionBytes(section: ElfSection): ByteArray {
        val end = section.fileOffset + section.fileSize
        if (section.fileOffset < 0 || section.fileSize < 0 || end > bytes.size) throw DwarfParseException("ELF section out of bounds")
        return bytes.copyOfRange(section.fileOffset.toInt(), end.toInt())
    }

    private fun readBuildId(c: BinaryCursor, sections: List<ElfSection>, raw: List<RawSection>): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        return try {
            val n = BinaryCursor(sectionBytesPublic(raw[sections.indexOf(note)]), littleEndian = little)
            val namesz = n.u32().toInt(); val descsz = n.u32().toInt(); val type = n.u32().toInt()
            val name = n.bytes((namesz + 3) and 3.inv())
            val desc = n.bytes(descsz)
            if (type == 3 && String(name).trimEnd('\u0000') == "GNU") desc.joinToString("") { "%02x".format(it) } else null
        } catch (_: Exception) { null }
    }
}
