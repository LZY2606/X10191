package compass

import compass.dwarf.*

/** CU with a zero-length subprogram at 0x1020 nested against outer [0x1000..0x1040). */
object ZeroLenFixture {
    fun build(): ByteArray {
        val fb = FixtureBuilder()
        val abbr = ByteArrayBuilder().apply {
            // 1 CU with children, stmt_list/data4, two strings
            uleb(1); uleb(0x11); u8(1)
            uleb(DW_AT_stmt_list); uleb(DW_FORM_data4)
            uleb(DW_AT_name); uleb(DW_FORM_string)
            uleb(DW_AT_comp_dir); uleb(DW_FORM_string)
            uleb(0); uleb(0)
            // 2 subprogram outer: low_pc addr + high_pc data4 (size)
            uleb(2); uleb(0x2e); u8(1)
            uleb(DW_AT_name); uleb(DW_FORM_string)
            uleb(DW_AT_low_pc); uleb(DW_FORM_addr)
            uleb(DW_AT_high_pc); uleb(DW_FORM_data4)
            uleb(0); uleb(0)
            // 3 zero-length subprogram "point": low=0x1020, high=const 0
            uleb(3); uleb(0x2e); u8(0)
            uleb(DW_AT_name); uleb(DW_FORM_string)
            uleb(DW_AT_low_pc); uleb(DW_FORM_addr)
            uleb(DW_AT_high_pc); uleb(DW_FORM_data4)
            uleb(0); uleb(0)
            uleb(0)
        }.build()
        fb.section(".debug_abbrev", abbr)
        val info = ByteArrayBuilder().apply {
            val body = ByteArrayBuilder().apply {
                uleb(1); u32(0); cstr("z.c"); cstr("/z")
                uleb(2); cstr("outer"); u64(0x1000); u32(0x40)
                uleb(3); cstr("point"); u64(0x1020); u32(0) // zero length
                uleb(0); uleb(0)
            }.build()
            u32((2 + 4 + 1 + body.size).toLong()); u16(4); u32(0); u8(8)
            bytes(body)
        }.build()
        fb.section(".debug_info", info)
        return fb.build()
    }
}

/** Two identical CUs whose functions both cover 0x1000..0x1040. */
object TwoCusFixture {
    fun build(): ByteArray {
        val fb = FixtureBuilder()
        val abbr = ByteArrayBuilder().apply {
            uleb(1); uleb(0x11); u8(1)
            uleb(DW_AT_name); uleb(DW_FORM_string)
            uleb(DW_AT_comp_dir); uleb(DW_FORM_string)
            uleb(0); uleb(0)
            uleb(2); uleb(0x2e); u8(0)
            uleb(DW_AT_name); uleb(DW_FORM_string)
            uleb(DW_AT_low_pc); uleb(DW_FORM_addr)
            uleb(DW_AT_high_pc); uleb(DW_FORM_data4)
            uleb(0); uleb(0)
            uleb(0)
        }.build()
        fb.section(".debug_abbrev", abbr)
        fun unit(n: String, fn: String) = ByteArrayBuilder().apply {
            val body = ByteArrayBuilder().apply {
                uleb(1); cstr(n); cstr("/p")
                uleb(2); cstr(fn); u64(0x1000); u32(0x40)
                uleb(0); uleb(0)
            }.build()
            u32((2 + 4 + 1 + body.size).toLong()); u16(4); u32(0); u8(8)
            bytes(body)
        }.build()
        val combined = unit("a.c", "fnA") + unit("b.c", "fnB")
        fb.section(".debug_info", combined)
        return fb.build()
    }
}
