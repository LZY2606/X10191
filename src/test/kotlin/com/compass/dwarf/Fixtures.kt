package com.compass.dwarf

import java.io.ByteArrayOutputStream

class ByteBuilder {
    private val out = ByteArrayOutputStream()
    val size get() = out.size()
    fun u8(value: Int): ByteBuilder { out.write(value and 0xff); return this }
    fun u16(value: Int): ByteBuilder { u8(value); u8(value ushr 8); return this }
    fun u32(value: Long): ByteBuilder { repeat(4) { out.write(((value ushr (8 * it)) and 0xff).toInt()) }; return this }
    fun u64(value: Long): ByteBuilder { repeat(8) { out.write(((value ushr (8 * it)) and 0xff).toInt()) }; return this }
    fun bytes(values: List<Int>): ByteBuilder { values.forEach(out::write); return this }
    fun raw(values: ByteArray): ByteBuilder { out.write(values); return this }
    fun text(value: String): ByteBuilder = raw(value.toByteArray()).u8(0)
    fun uleb(value: Long): ByteBuilder {
        var remaining = value
        while (true) {
            var byte = (remaining and 0x7f).toInt()
            remaining = remaining ushr 7
            if (remaining != 0L) byte = byte or 0x80
            out.write(byte)
            if (remaining == 0L) break
        }
        return this
    }
    fun build(): ByteArray = out.toByteArray()
}

object Fixtures {
    const val AT_NAME = 0x03
    const val AT_STMT_LIST = 0x10
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_COMP_DIR = 0x1b
    const val AT_RANGES = 0x55
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_SEGMENT = 0x68
    const val AT_RNGLISTS = 0x63
    const val AT_DWO_NAME = 0x76
    const val AT_DWO_ID = 0x75
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val TAG_CU = 0x11
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINE = 0x1d
    const val FORM_ADDR = 0x01
    const val FORM_STRING = 0x08
    const val FORM_DATA1 = 0x0b
    const val FORM_DATA4 = 0x06
    const val FORM_DATA8 = 0x07
    const val FORM_REF4 = 0x13
    const val FORM_SEC_OFFSET = 0x17
    const val FORM_RNGLISTX = 0x23

    fun elf(sections: Map<String, ByteArray>): ByteArray {
        val layout = linkedMapOf<String, ByteArray>()
        layout[""] = byteArrayOf(0)
        layout.putAll(sections)
        val nameBuilder = ByteBuilder()
        val nameOffsets = mutableMapOf<String, Long>()
        layout.keys.forEach { name ->
            nameOffsets[name] = nameBuilder.size.toLong()
            nameBuilder.text(name)
        }
        val shstr = nameBuilder.build()
        layout[".shstrtab"] = shstr
        var offset = 64L
        val offsets = layout.mapValues { offset.also { offset += it.value.size.toLong() } }
        val shOffset = offset
        val header = ByteBuilder()
            .bytes(listOf(0x7f, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            .u16(2).u16(62).u32(1).u64(0).u64(0).u64(shOffset).u32(0).u16(64).u16(0).u16(64)
            .u16(layout.size).u16(layout.keys.indexOf(".shstrtab"))
        val out = ByteArrayOutputStream()
        out.write(header.build())
        while (out.size() < 64) out.write(0)
        layout.values.forEach(out::write)
        layout.forEach { (name, payload) ->
            val sectionHeader = ByteBuilder().u32(nameOffsets.getValue(name)).u32(1).u64(0).u64(0)
                .u64(offsets.getValue(name)).u64(payload.size.toLong()).u32(0).u32(0).u64(1).u64(0).build()
            out.write(sectionHeader)
        }
        return out.toByteArray()
    }

    fun abbrev(vararg entries: ByteBuilder.() -> Unit): ByteArray {
        val builder = ByteBuilder()
        entries.forEachIndexed { index, entry ->
            builder.uleb(index + 1L)
            builder.entry()
        }
        return builder.uleb(0).build()
    }

    private fun cuAttrs(extra: ByteBuilder.() -> Unit = {}) {
        uleb(AT_NAME.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_COMP_DIR.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_STMT_LIST.toLong()); uleb(FORM_SEC_OFFSET.toLong())
        extra()
        uleb(0); uleb(0)
    }

    fun simpleAbbrev(highForm: Int = FORM_ADDR, cuExtra: ByteBuilder.() -> Unit = {}): ByteArray = abbrev({
        uleb(TAG_CU.toLong()); u8(1); cuAttrs(cuExtra)
    }, {
        uleb(TAG_SUBPROGRAM.toLong()); u8(0)
        uleb(AT_NAME.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_LOW_PC.toLong()); uleb(FORM_ADDR.toLong())
        uleb(AT_HIGH_PC.toLong()); uleb(highForm.toLong())
        uleb(0); uleb(0)
    })

    fun rangeAbbrev(v5: Boolean = false): ByteArray = abbrev({
        uleb(TAG_CU.toLong()); u8(1)
        uleb(AT_NAME.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_COMP_DIR.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_STMT_LIST.toLong()); uleb(FORM_SEC_OFFSET.toLong())
        if (v5) { uleb(AT_RNGLISTS.toLong()); uleb(FORM_SEC_OFFSET.toLong()) }
        uleb(0); uleb(0)
    }, {
        uleb(TAG_SUBPROGRAM.toLong()); u8(0)
        uleb(AT_NAME.toLong()); uleb(FORM_STRING.toLong())
        uleb(AT_RANGES.toLong()); uleb(if (v5) FORM_RNGLISTX.toLong() else FORM_SEC_OFFSET.toLong())
        uleb(0); uleb(0)
    })

    fun inlineAbbrev(): ByteArray = abbrev({
        uleb(TAG_CU.toLong()); u8(1); cuAttrs()
    }, {
        uleb(TAG_SUBPROGRAM.toLong()); u8(0)
        uleb(AT_NAME.toLong()); uleb(FORM_STRING.toLong())
        uleb(0); uleb(0)
    }, {
        uleb(TAG_SUBPROGRAM.toLong()); u8(1)
        uleb(0); uleb(0)
    }, {
        uleb(TAG_INLINE.toLong()); u8(0)
        uleb(AT_ABSTRACT_ORIGIN.toLong()); uleb(FORM_REF4.toLong())
        uleb(AT_LOW_PC.toLong()); uleb(FORM_ADDR.toLong())
        uleb(AT_HIGH_PC.toLong()); uleb(FORM_DATA1.toLong())
        uleb(AT_CALL_FILE.toLong()); uleb(FORM_DATA1.toLong())
        uleb(AT_CALL_LINE.toLong()); uleb(FORM_DATA1.toLong())
        uleb(0); uleb(0)
    })

    fun v4Info(dies: ByteBuilder.() -> ByteBuilder, abbrev: ByteArray, lineOffset: Long = 0): ByteArray {
        val dieBytes = ByteBuilder().u8(1).text("main.c").text("/work").u32(lineOffset).dies().u8(0).build()
        return ByteBuilder().u32((dieBytes.size + 7).toLong()).u16(4).u32(1).u32(0).u8(0).raw(dieBytes).build()
    }

    fun v5Info(dies: ByteBuilder.() -> ByteBuilder, lineOffset: Long = 0): ByteArray {
        val dieBytes = ByteBuilder().u8(1).text("main.c").text("/work").u32(lineOffset).dies().u8(0).build()
        return ByteBuilder().u32((dieBytes.size + 5).toLong()).u16(5).u8(1).u8(1).u32(0).raw(dieBytes).build()
    }

    fun v4Line(vararg addresses: Long): ByteArray {
        val program = ByteBuilder()
        addresses.forEach { address ->
            program.bytes(listOf(0, 5, 2)).u32(address).u8(13)
            program.bytes(listOf(0, 1, 1))
        }
        val dirs = ByteBuilder().text("/work").u8(0)
        val files = ByteBuilder().text("main.c").uleb(1).uleb(0).uleb(0).u8(0)
        val header = ByteBuilder().u8(1).u8(1).u8(1).u8(-5).u8(14).u8(12)
            .bytes(listOf(0,1,1,1,1,0,0,0,1,0,1)).raw(dirs.build()).raw(files.build())
        return ByteBuilder().u32((header.size + program.size).toLong()).u16(4).raw(header.build()).raw(program.build()).build()
    }

    fun v5Line(address: Long): ByteArray {
        val lineStrings = ByteBuilder().u8(0).text("main.c").build()
        val program = ByteBuilder().bytes(listOf(0, 5, 2)).u32(address).u8(13).bytes(listOf(0, 1, 1))
        val header = ByteBuilder()
            .u8(1).u8(1).u8(1).u8(-5).u8(14).u8(12)
            .bytes(listOf(0,1,1,1,1,0,0,0,1,0,1))
            .u8(1).uleb(1).uleb(0x1f).uleb(1).u32(0)
            .u8(1).uleb(1).uleb(2).uleb(0x0b).u8(1)
        return ByteBuilder().u32((header.size + program.size).toLong()).u16(5).u8(4).u8(0)
            .u32(header.size.toLong()).raw(header.build()).raw(program.build()).build()
    }

    fun v4Ranges(): ByteArray = ByteBuilder()
        .u32(0xffffffffL).u32(0x401000L)
        .u32(0x10).u32(0x20).u32(0).u32(0).build()

    fun v5Rnglists(): ByteArray {
        val entries = ByteBuilder().u8(7).u32(0x401010L).uleb(0x10).u8(0)
        return ByteBuilder().u32((entries.size + 4).toLong()).u16(5).u8(4).u8(0).u32(0).raw(entries.build()).build()
    }
}
