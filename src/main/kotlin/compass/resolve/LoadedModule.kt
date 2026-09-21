package compass.resolve

import compass.dwarf.AddrRange
import compass.dwarf.CompilationUnit
import compass.dwarf.DebugBundle
import compass.dwarf.Die
import compass.dwarf.DwTag
import compass.dwarf.LineProgram
import compass.dwarf.LineRow
import compass.dwarf.LineSequence
import compass.dwarf.tagName
import compass.elf.SymbolInfo
import compass.util.U64

class LoadedModule(val id: Long, val name: String, val bundle: DebugBundle) {

    /** Prefer the lowest PT_LOAD vaddr, else lowest executable section, else 0. */
    fun preferredBase(): U64 {
        val segs = bundle.elf.segments
        if (segs.isNotEmpty()) {
            return segs.minByOrNull { it.vaddr }!!.vaddr
        }
        val allocated = bundle.elf.sections.filter { it.size.v != 0L && it.addr.v != 0L }
        return allocated.minByOrNull { it.addr }?.addr ?: U64.ZERO
    }

    fun cuAtOffset(off: U64?): CompilationUnit? {
        if (off == null) return null
        return bundle.cus.firstOrNull { it.offset == off }
    }

    /** Resolve skeleton -> split companion CU when present. */
    fun effectiveCu(cu: CompilationUnit): CompilationUnit {
        return bundle.splitLinks[cu.offset]?.let { off -> bundle.cus.firstOrNull { it.offset == off } } ?: cu
    }

    fun lineProgramFor(cu: CompilationUnit): LineProgram? =
        bundle.linePrograms.firstOrNull { it.cuOffset == cu.offset }

    /** Enclosing scope DIEs (subprogram/inline/lexical block with a range) for the given addr. */
    fun scopeDies(cu: CompilationUnit, segment: Int, addr: U64): List<Die> {
        val out = ArrayList<Die>()
        for (die in cu.dies) {
            if (die.tag != DwTag.SUBPROGRAM && die.tag != DwTag.INLINED_SUBROUTINE && die.tag != DwTag.LEXICAL_BLOCK) continue
            if (die.ranges.isEmpty()) continue
            for (rg in die.ranges) {
                val hit = rg.contains(segment, addr) || (rg.zeroLength && rg.start == addr)
                if (hit) { out += die; break }
            }
        }
        return out
    }

    fun symbols(): List<SymbolInfo> = bundle.elf.symbols
}
