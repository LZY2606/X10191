package compass.dwarf

/**
 * 纯本地 ELF 解析：64/32 位、小端（目标平台常见组合），大端会显式报诊断。
 * 提取 section 头、PT_LOAD 段、PT_NOTE 中的 GNU Build ID，以及调试 section 的字节摘要。
 */
class ElfParser(private val file: ByteArray) {
    private val diagnostics = mutableListOf<Diagnostic>()

    fun parse(): Triple<ElfInfo, Map<String, ByteArray>, List<Diagnostic>> {
        if (file.size < 16 || file[0] != 0x7f.toByte() || file[1] != 'E'.code.toByte() ||
            file[2] != 'L'.code.toByte() || file[3] != 'F'.code.toByte()
        ) {
            throw CursorException("不是 ELF 文件（魔数不匹配）")
        }
        val elfClass = file[4].toInt() and 0xff
        val endian = file[5].toInt() and 0xff
        if (endian != 1) {
            diagnostics += Diagnostic("ERROR", "elf", "暂不支持大端 ELF（EI_DATA=$endian）")
            throw CursorException("不支持的 ELF 端序")
        }
        val is64 = elfClass == 2
        if (elfClass != 1 && elfClass != 2) throw CursorException("未知 EI_CLASS=$elfClass")

        val machine: Int
        val entry: Long
        val type: Int
        val shoff: Long
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        val phoff: Long
        val phentsize: Int
        val phnum: Int

        if (is64) {
            val v = ByteView(file)
            type = v.u16(16)
            machine = v.u16(18)
            entry = v.u64(24)
            phoff = v.u64(32)
            shoff = v.u64(40)
            phentsize = v.u16(54)
            phnum = v.u16(56)
            shentsize = v.u16(58)
            shnum = v.u16(60)
            shstrndx = v.u16(62)
        } else {
            val v = ByteView(file)
            type = v.u16(16)
            machine = v.u16(18)
            entry = v.u32(24)
            phoff = v.u32(28)
            shoff = v.u32(32)
            phentsize = v.u16(42)
            phnum = v.u16(44)
            shentsize = v.u16(46)
            shnum = v.u16(48)
            shstrndx = v.u16(50)
        }

        if (shoff <= 0 || shnum == 0) {
            diagnostics += Diagnostic("ERROR", "elf", "ELF 无 section 头表")
            throw CursorException("ELF 无 section 头表")
        }

        val v = ByteView(file)
        // section 头
        data class RawSec(
            val nameOff: Int, val type: Long, val flags: Long, val addr: Long,
            val offset: Long, val size: Long, val link: Int, val info: Long,
            val align: Long, val entsize: Long
        )
        val raw = ArrayList<RawSec>(shnum)
        try {
            for (i in 0 until shnum) {
                val b = shoff + i * shentsize
                if (is64) {
                    raw += RawSec(
                        v.u32(b).toInt(), v.u64(b + 4), v.u64(b + 8), v.u64(b + 16),
                        v.u64(b + 24), v.u64(b + 32), v.u64(b + 40).toInt(),
                        v.u64(b + 44), v.u64(b + 48), v.u64(b + 56)
                    )
                } else {
                    raw += RawSec(
                        v.u32(b).toInt(), v.u32(b + 4), v.u32(b + 8), v.u32(b + 12),
                        v.u32(b + 16), v.u32(b + 20), v.u32(b + 24).toInt(),
                        v.u32(b + 28), v.u32(b + 32), v.u32(b + 36)
                    )
                }
            }
        } catch (e: CursorException) {
            diagnostics += Diagnostic("ERROR", "elf", "section 头表越界: ${e.message}")
            throw e
        }

        // shstrtab
        val shstr = raw.getOrNull(shstrndx)
        val shstrView: ByteView? = if (shstr != null && shstrndx > 0 && shstr.size > 0)
            boundedSection(file, shstr.offset, shstr.size) else null

        val debugNames = setOf(
            ".debug_info", ".debug_abbrev", ".debug_str", ".debug_line",
            ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists",
            ".debug_line_str", ".debug_cu_index", ".debug_tu_index",
            ".zdebug_info", ".zdebug_abbrev", ".zdebug_str", ".zdebug_line"
        )

        val sections = ArrayList<SectionInfo>()
        val sectionBytes = LinkedHashMap<String, ByteArray>()
        for ((i, s) in raw.withIndex()) {
            val name = if (shstrView != null) {
                try { shstrView.cstring(s.nameOff) } catch (e: CursorException) { "<bad:$i>" }
            } else "<noname:$i>"
            val nominalPresent = s.size > 0 && s.type != SHT.NOBITS && s.offset > 0
            val bytes: ByteArray? = if (nominalPresent && (name in debugNames || name == ".note.gnu.build-id")) {
                try {
                    boundedSection(file, s.offset, s.size).let { it.bytes(0, it.size) }
                } catch (e: CursorException) {
                    diagnostics += Diagnostic("WARNING", "elf", "section $name 字节越界: ${e.message}")
                    null
                }
            } else null
            if (bytes != null && name in debugNames) sectionBytes[name] = bytes
            sections += SectionInfo(
                name = name,
                type = s.type,
                fileOffset = s.offset,
                size = s.size,
                link = s.link,
                addressAlign = s.align,
                dataDigest = if (bytes != null) Util.shortDigest(bytes) else "",
                present = nominalPresent && (name !in debugNames || bytes != null)
            )
        }

        // 程序头（用于 load bias 计算）
        val segments = ArrayList<ProgramSegment>()
        if (phoff > 0L && phentsize > 0) {
            try {
                for (i in 0 until phnum) {
                    val b = phoff + i * phentsize
                    if (is64) {
                        segments += ProgramSegment(
                            type = v.u32(b), flags = v.u32(b + 4), v.u64(b + 8),
                            v.u64(b + 16), v.u64(b + 32), v.u64(b + 40)
                        )
                    } else {
                        segments += ProgramSegment(
                            type = v.u32(b), flags = v.u32(b + 24), v.u32(b + 4),
                            v.u32(b + 8), v.u32(b + 16), v.u32(b + 20)
                        )
                    }
                }
            } catch (e: CursorException) {
                diagnostics += Diagnostic("WARNING", "elf", "程序头表越界: ${e.message}")
            }
        }

        val buildId = extractBuildId(sections, sectionBytes)

        val info = ElfInfo(
            elfClass = elfClass,
            endian = endian,
            machine = machine,
            entry = entry,
            type = type,
            sections = sections,
            segments = segments,
            buildId = buildId,
            fileDigest = Util.sha256(file)
        )
        return Triple(info, sectionBytes, diagnostics)
    }

    private fun boundedSection(file: ByteArray, offset: Long, size: Long): ByteView {
        val off = offset.toInt()
        val len = size.toInt()
        if (offset < 0 || size < 0 || off.toLong() != offset || len.toLong() != size ||
            off < 0 || len < 0 || off + len > file.size
        ) throw CursorException("section 文件范围非法 offset=$offset size=$size")
        return ByteView(file, off, len)
    }

    /** 从 .note.gnu.build-id 提取 NT_GNU_BUILD_ID (n_type=3, name="GNU")。 */
    private fun extractBuildId(sections: List<SectionInfo>, bytes: Map<String, ByteArray>): String? {
        val sec = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        val data = bytes[".note.gnu.build-id"] ?: return null
        return try {
            val c = Cursor(ByteView(data))
            while (c.remaining >= 12) {
                val namesz = c.u32().toInt()
                val descsz = c.u32().toInt()
                val ntype = c.u32().toInt()
                val name = c.take(namesz).toString(Charsets.US_ASCII).trimEnd(0.toChar())
                if (c.pos and 3 != 0) c.take(4 - (c.pos and 3))
                val desc = c.take(descsz)
                if (c.pos and 3 != 0) c.take(4 - (c.pos and 3))
                if (name == "GNU" && ntype == 3) return Util.hex(desc)
            }
            null
        } catch (e: CursorException) {
            diagnostics += Diagnostic("WARNING", "elf", "build-id note 解析失败: ${e.message}")
            null
        }
    }
}
