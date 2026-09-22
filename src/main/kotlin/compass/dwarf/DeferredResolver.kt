package compass.dwarf

/**
 * Resolves strx/addrx deferred values in split CUs using the linked
 * skeleton's .debug_addr (and v4 GNU debug_str_offsets). When the dwo is
 * missing the deferred forms stay unresolved and ranges relying on them are
 * dropped with a recorded issue.
 */
object DeferredResolver {
    fun resolve(file: ParsedFile, all: Collection<ParsedFile>) {
        for (unit in file.units) {
            val skeleton = linkedSkeleton(unit, all)
            walk(unit.root) { die ->
                for ((_, attr) in die.attributes) {
                    val v = attr.value
                    when {
                        v is FormValue.DeferredAddrIndex -> {
                            val resolved = skeleton?.let { readAddr(it, unit, v.index) }
                            if (resolved != null) attr.value = FormValue.Address(resolved)
                            else unit.issues.add(ParseIssue("warning", "die+${die.offset}",
                                "addrx[${v.index}] unresolved: import the matching .dwo skeleton"))
                        }
                        v is FormValue.DeferredStrIndex -> {
                            val text = skeleton?.let { readStr(it, unit, v.index) }
                                ?: file.sections.str?.let { fallbackLocalStr(file, v.index) }
                            if (text != null) attr.value = FormValue.Text(text)
                            else unit.issues.add(ParseIssue("warning", "die+${die.offset}",
                                "strx[${v.index}] unresolved"))
                        }
                    }
                }
            }
        }
        // Rebuild scopes now that indices resolved (cheap; fixtures are small).
        file.scopes.clear()
        for (unit in file.units) {
            if (unit.root.tag == 0) continue
            rewalk(unit.root, unit, file)
        }
    }

    private fun linkedSkeleton(unit: CompUnit, all: Collection<ParsedFile>): ParsedFile? {
        if (!unit.isSplit) return null
        val id = unit.dwoId ?: unit.root.num(DW.AT_GNU_dwo_id) ?: return null
        return all.firstOrNull { f ->
            f.units.any { it.isSkeleton && (it.dwoId ?: it.root.num(DW.AT_GNU_dwo_id)) == id }
        }
    }

    private fun readAddr(skeletonFile: ParsedFile, dwoUnit: CompUnit, index: Long): Long? {
        val sec = skeletonFile.sections.addr ?: return null
        val skel = skeletonFile.units.first {
            it.isSkeleton && (it.dwoId ?: it.root.num(DW.AT_GNU_dwo_id)) ==
                (dwoUnit.dwoId ?: dwoUnit.root.num(DW.AT_GNU_dwo_id))
        }
        val base = skel.addrBase
        val size = dwoUnit.addressSize
        val at = (base + index * size).toInt()
        if (at + size > sec.size) return null
        return sec.subReader(at, size).uword(size)
    }

    private fun readStr(skeletonFile: ParsedFile, dwoUnit: CompUnit, index: Long): String? {
        // GNU v4: str_offsets live in the dwo; DWARF5: skeleton has .debug_str_offsets
        val so = dwoUnit.fileId.let { skeletonFile.sections.strOffsets }
            ?: return null
        val base = 0L
        val size = dwoUnit.addressSize.coerceAtLeast(4)
        val at = (base + index * size).toInt()
        if (at + size > so.size) return null
        val rr = so.subReader(at, size)
        val off = if (size == 4) rr.u4().toLong() and 0xffffffffL else rr.u8()
        return skeletonFile.sections.str?.stringAt(off.toInt())
    }

    private fun fallbackLocalStr(file: ParsedFile, index: Long): String? {
        val so = file.sections.strOffsets ?: return null
        val at = index.toInt() * 4
        if (at + 4 > so.size) return null
        val off = so.subReader(at, 4).u4().toLong() and 0xffffffffL
        return file.sections.str?.stringAt(off.toInt())
    }

    private fun walk(die: DieNode, action: (DieNode) -> Unit) {
        action(die)
        die.children.forEach { walk(it, action) }
    }

    private fun rewalk(die: DieNode, unit: CompUnit, parsed: ParsedFile) {
        if (die.isScopeWithCode) {
            val ranges = try {
                RangeExtractor.rangesFor(die, unit, parsed)
            } catch (e: Exception) {
                unit.issues.add(ParseIssue("error", "die+${die.offset}",
                    "range extraction failed: ${e.message}"))
                emptyList()
            }
            val inlineDepth = if (die.tag == DW.TAG_inlined_subroutine) {
                var d = 0
                var p = die.parent
                while (p != null) { if (p.isScopeWithCode) d++; p = p.parent }
                d
            } else 0
            if (ranges.isNotEmpty() || die.tag == DW.TAG_inlined_subroutine)
                parsed.scopes.add(ScopeDie(unit, die, ranges, inlineDepth))
        }
        die.children.forEach { rewalk(it, unit, parsed) }
    }
}
