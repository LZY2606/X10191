package compass

import compass.dwarf.DwarfFixture.Companion.AT_GNU_dwo_id
import compass.dwarf.DwarfFixture.Companion.AT_GNU_dwo_name
import compass.dwarf.DwarfFixture.Companion.AT_GNU_addr_base
import compass.dwarf.DwarfFixture.Companion.AT_abstract_origin
import compass.dwarf.DwarfFixture.Companion.AT_addr_base
import compass.dwarf.DwarfFixture.Companion.AT_call_column
import compass.dwarf.DwarfFixture.Companion.AT_call_file
import compass.dwarf.DwarfFixture.Companion.AT_call_line
import compass.dwarf.DwarfFixture.Companion.AT_dwo_id
import compass.dwarf.DwarfFixture.Companion.AT_dwo_name
import compass.dwarf.DwarfFixture.Companion.AT_high_pc
import compass.dwarf.DwarfFixture.Companion.AT_inline
import compass.dwarf.DwarfFixture.Companion.AT_low_pc
import compass.dwarf.DwarfFixture.Companion.AT_name
import compass.dwarf.DwarfFixture.Companion.AT_ranges
import compass.dwarf.DwarfFixture.Companion.AT_rnglists
import compass.dwarf.DwarfFixture.Companion.AT_rnglists_base
import compass.dwarf.DwarfFixture.Companion.AT_stmt_list
import compass.dwarf.DwarfFixture.Companion.AT_str_offsets_base
import compass.dwarf.DwarfFixture.Companion.DieBuilder
import compass.dwarf.DwarfFixture.Companion.F_GNU_addr_index
import compass.dwarf.DwarfFixture.Companion.F_GNU_rnglistx
import compass.dwarf.DwarfFixture.Companion.F_GNU_str_index
import compass.dwarf.DwarfFixture.Companion.F_addr
import compass.dwarf.DwarfFixture.Companion.F_addrx
import compass.dwarf.DwarfFixture.Companion.F_data1
import compass.dwarf.DwarfFixture.Companion.F_data8
import compass.dwarf.DwarfFixture.Companion.F_flag_present
import compass.dwarf.DwarfFixture.Companion.F_rnglistx
import compass.dwarf.DwarfFixture.Companion.F_sec_offset
import compass.dwarf.DwarfFixture.Companion.F_string
import compass.dwarf.DwarfFixture.Companion.F_udata
import compass.fixture.DwarfFixture
import compass.fixture.ElfWriter
import java.io.ByteArrayOutputStream

/** Tiny generated DWARF fixtures for the test suite. */
object Fixtures {

    /** DWARF5: two overlapping functions (one wide, one narrow), two line sequences. */
    fun dwarf5Overlapping(): ByteArray {
        val fx = DwarfFixture(version = 5)
        fx.lineProgram(0) {
            val main = file("main.c")
            setAddress(0x401000); setFile(main.toLong()); setColumn(1)
            special(0); advancePc(1); special(1); advancePc(1); copy()
            setColumn(5); advancePc(2); special(2)
            endSequence()
            setAddress(0x402000); setFile(main.toLong()); setColumn(1)
            special(0); advancePc(1); special(1)
            endSequence()
        }
        fx.rootDie(DwarfFixture.TAG_compile_unit) {
            attr(AT_name, F_string, "overlap.cu")
            attr(AT_stmt_list, F_sec_offset, 0L)
            attr(AT_low_pc, F_addr, 0x401000L)
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "wide_func")
                attr(AT_low_pc, F_addr, 0x401000L)
                attr(AT_high_pc, F_addr, 0x401060L) // absolute
            })
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "narrow_func")
                attr(AT_low_pc, F_addr, 0x401020L)
                attr(AT_high_pc, F_data8, 0x10L) // constant length
            })
        }
        return ElfWriter().build(fx.assembleSections())
    }

    /** DWARF4: .debug_ranges with two fragments and a zero-length range. */
    fun dwarf4Ranges(): ByteArray {
        val fx = DwarfFixture(version = 4)
        fx.lineProgram(0) {
            val f = file("r4.c")
            setAddress(0x401000); setFile(f.toLong())
            special(0); advancePc(2); special(1); advancePc(1); copy(); endSequence()
            setAddress(0x403000); special(0); advancePc(1); special(2); endSequence()
        }
        val ranges = ByteArrayOutputStream()
        fun pair(a: Long, b: Long) { DwarfFixture.writeU32(ranges, a); DwarfFixture.writeU32(ranges, b) }
        pair(0x1000, 0x1010)
        pair(0x3000, 0x3000)
        pair(0, 0)
        fx.rootDie(DwarfFixture.TAG_compile_unit) {
            attr(AT_name, F_string, "r4.cu")
            attr(AT_stmt_list, F_sec_offset, 0L)
            attr(AT_low_pc, F_addr, 0x400000L)
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "fragmented")
                attr(AT_ranges, F_sec_offset, 0L)
            })
        }
        return ElfWriter().build(fx.assembleSections(rangesBytes = ranges.toByteArray()))
    }

    /** DWARF5: outer -> inlined leaf_helper via DW_FORM_ref1 and call site info. */
    fun dwarf5InlineChain(): ByteArray {
        val fx = DwarfFixture(version = 5)
        fx.lineProgram(0) {
            val f = file("inline.c")
            setAddress(0x401000); setFile(f.toLong())
            special(0); advancePc(2); copy()
            setColumn(8); advancePc(2); special(1)
            setColumn(16); advancePc(2); special(2); endSequence()
        }
        lateinit var leaf: DieBuilder
        fx.rootDie(DwarfFixture.TAG_compile_unit) {
            attr(AT_name, F_string, "inline.cu")
            attr(AT_stmt_list, F_sec_offset, 0L)
            leaf = DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "leaf_helper")
                attr(AT_inline, F_data1, 1L)
                attr(AT_low_pc, F_addr, 0x401000L)
                attr(AT_high_pc, F_data8, 0x30L)
            }
            child(leaf)
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "outer")
                attr(AT_low_pc, F_addr, 0x401000L)
                attr(AT_high_pc, F_data8, 0x30L)
                child(DieBuilder(DwarfFixture.TAG_inlined_subroutine).apply {
                    attr(AT_abstract_origin, 0x11 /*ref1*/, leaf)
                    attr(AT_low_pc, F_addr, 0x401008L)
                    attr(AT_high_pc, F_data8, 0x10L)
                    attr(AT_call_file, F_data1, 0L)
                    attr(AT_call_line, F_udata, 42L)
                    attr(AT_call_column, F_udata, 8L)
                })
            })
        }
        return ElfWriter().build(fx.assembleSections())
    }

    // ---- corruption / edge cases ----

    /** ELF with an abbrev declaring a fabricated unknown form: DIE tree must truncate safely. */
    fun unknownForm(): ByteArray {
        val good = dwarf5Overlapping()
        // Easier: hand-build minimal bytes: abbrev declares CU code 1 with attr 0x03/form 0x7e
        val abbrev = ByteArrayOutputStream().apply {
            DwarfFixture.writeUleb(this, 1)
            DwarfFixture.writeUleb(this, 0x11) // TAG_compile_unit
            write(0) // no children
            DwarfFixture.writeUleb(this, 0x03) // AT_name
            DwarfFixture.writeUleb(this, 0x7e) // UNKNOWN FORM
            DwarfFixture.writeUleb(this, 0); DwarfFixture.writeUleb(this, 0)
            DwarfFixture.writeUleb(this, 0)
        }
        val body = ByteArrayOutputStream().apply {
            DwarfFixture.writeU16(this, 5); write(1); write(8)
            DwarfFixture.writeU32(this, 0) // abbrev offset
        }
        val info = ByteArrayOutputStream().apply {
            DwarfFixture.writeU32(this, (body.size() + 1).toLong()) // +1 for the code byte
            write(body.toByteArray()); DwarfFixture.writeUleb(this, 1)
            // random garbage that must NOT be interpreted
            write(byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc, 0xdd))
        }
        return ElfWriter().build(listOf(
            ElfWriter.Section(".debug_abbrev", abbrev.toByteArray()),
            ElfWriter.Section(".debug_info", info.toByteArray())
        ))
    }

    /** ref1 pointing far beyond the CU: must resolve to unresolved, never crash. */
    fun outOfBoundsRef(): ByteArray {
        val fx = DwarfFixture(version = 5)
        fx.rootDie(DwarfFixture.TAG_compile_unit) {
            attr(AT_name, F_string, "oob.cu")
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_abstract_origin, 0x11, 0x60L) // bogus local offset
                attr(AT_low_pc, F_addr, 0x401000L)
                attr(AT_high_pc, F_data8, 0x8L)
            })
        }
        return ElfWriter().build(fx.assembleSections())
    }

    // ---- split DWARF (v5) ----

    data class SplitPair(val skeleton: ByteArray, val dwo: ByteArray)

    fun splitDwarf5(): SplitPair {
        val dwoId = 0x1122334455667788L
        // skeleton ELF: contains .debug_addr + CU skeleton with ranges via addrx
        val sk = DwarfFixture(version = 5)
        val addrIdx = sk.addAddr(0x401000L)
        sk.lineProgram(0) {
            val f = file("split.c")
            setAddress(0x401000); setFile(f.toLong())
            special(0); advancePc(1); special(1); endSequence()
        }
        // .debug_rnglists with one start_length list
        val rng = buildRngListsV5(listOf(0x00 to 0x08)) // RLE_offset_pair relative? use startx form below
        val rngBlob = buildRngListsV5Startx(listOf(Triple(addrIdx, 0x10L, 0)))
        sk.rootDie(DwarfFixture.TAG_skeleton_unit) {
            attr(AT_name, F_string, "split.c")
            attr(AT_dwo_name, F_string, "split.dwo")
            attr(AT_dwo_id, F_data8, dwoId)
            attr(AT_stmt_list, F_sec_offset, 0L)
            attr(AT_addr_base, F_sec_offset, 0L)
            attr(AT_rnglists_base, F_sec_offset, 0L)
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "skeleton_concrete")
                attr(AT_rnglists, F_rnglistx, 0L)
            })
        }
        // dwo file: split CU + inlined DIE using deferred addrx
        val dwo = DwarfFixture(version = 5)
        dwo.rootDie(DwarfFixture.TAG_split_compile_unit) {
            attr(AT_dwo_id, F_data8, dwoId)
            attr(AT_name, F_string, "split.c")
            child(DieBuilder(DwarfFixture.TAG_subprogram).apply {
                attr(AT_name, F_string, "inlined_in_dwo")
                attr(AT_low_pc, F_addrx, addrIdx) // deferred to skeleton
                attr(AT_high_pc, F_data8, 0x10L)
            })
        }
        return SplitPair(
            ElfWriter().build(sk.assembleSections(rnglistsBytes = rngBlob)),
            ElfWriter().build(dwo.assembleSections(dwoSuffix = true, includeLine = false))
        )
    }

    /** v5 .debug_rnglists with RLE_startx_length pairs. */
    private fun buildRngListsV5Startx(entries: List<Triple<Long, Long, Int>>): ByteArray {
        val list = ByteArrayOutputStream()
        for ((idx, len, _) in entries) {
            list.write(0x03) // RLE_startx_length
            DwarfFixture.writeUleb(list, idx)
            DwarfFixture.writeUleb(list, len)
        }
        list.write(0x00) // end
        val body = ByteArrayOutputStream()
        DwarfFixture.writeU16(body, 5); body.write(8); body.write(0)
        body.write(0); body.write(0) // no offset array
        body.write(list.toByteArray())
        val out = ByteArrayOutputStream()
        DwarfFixture.writeU32(out, body.size().toLong())
        out.write(body.toByteArray())
        return out.toByteArray()
    }

    private fun buildRngListsV5(@Suppress("UNUSED_PARAMETER") x: List<Pair<Int, Int>>): ByteArray =
        ByteArray(0)

    // ---- relocation: same CU, load bias applied at query time ----
    fun relocatableDwarf5(): ByteArray = dwarf5Overlapping()
}
