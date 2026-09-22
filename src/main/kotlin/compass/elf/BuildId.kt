package compass.elf

/** Extracts the GNU build-id note (NT_GNU_BUILD_ID) from PT_NOTE segments. */
object BuildId {
    fun extract(elf: ElfFile): String? {
        for (seg in elf.segments.filter { it.type == 4 }) {
            val sec = elf.sections.firstOrNull { it.name == ".note.gnu.build-id" }
            val bytes = sec?.bytes
                ?: run {
                    if (seg.offset < 0 || seg.offset + seg.filesz > elf.raw.size) continue
                    elf.raw.copyOfRange(seg.offset.toInt(), (seg.offset + seg.filesz).toInt())
                }
            parseNote(bytes, elf.bigEndian)?.let { return it }
        }
        return elf.sections.firstOrNull { it.name == ".note.gnu.build-id" }?.bytes
            ?.let { parseNote(it, elf.bigEndian) }
    }

    private fun parseNote(data: ByteArray, bigEndian: Boolean): String? {
        val r = ByteReader(data, bigEndian, "note")
        var guard = 0
        while (r.remaining() > 12 && guard++ < 100) {
            val namesz = r.u32().toInt()
            val descsz = r.u32().toInt()
            val type = r.u32().toInt()
            if (namesz < 0 || descsz < 0 || r.pos + namesz + descsz > data.size) return null
            val nameStart = r.pos
            val name = data.copyOfRange(nameStart, nameStart + namesz)
            r.pos += pad4(namesz)
            val descStart = r.pos
            val desc = r.bytes(descsz)
            r.pos = descStart + pad4(descsz)
            val nameStr = String(name).trimEnd(0.toChar())
            if (type == 3 && nameStr == "GNU") {
                return desc.joinToString("") { "%02x".format(it) }
            }
        }
        return null
    }

    private fun pad4(n: Int) = (n + 3) and 3.inv()
}
