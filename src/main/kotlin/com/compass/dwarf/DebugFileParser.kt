package com.compass.dwarf

object DebugFileParser {
    fun parse(bytes: ByteArray): DebugDocument {
        val elf = ElfReader(bytes).parse()
        val sections = elf.sections.filter { it.fileSize > 0 }.associate { section ->
            section.name to bytes.copyOfRange(section.fileOffset.toInt(), (section.fileOffset + section.fileSize).toInt())
        }
        return DwarfParser(sections, elf, elf.littleEndian).parse()
    }
}
