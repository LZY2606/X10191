package compass.dwarf

/**
 * Links skeleton CUs (executable) to split CUs (.dwo) using:
 *  - DWARF5: 64-bit DWO id
 *  - DWARF4 GNU fission: DW_AT_GNU_dwo_id
 * Missing partners leave the skeleton unlinked; the query layer then reports
 * which conclusions are still trustworthy (skeleton ranges/line, no inlines).
 */
object SplitLinker {
    fun link(all: Collection<ParsedFile>) {
        for (f in all) for (u in f.units) {
            u.linkedDwoFileId = null
            u.linkedDwoUnitOffset = null
        }
        data class Key(val id: Long)
        val splitById = HashMap<Long, Pair<Long, CompUnit>>()
        for (f in all) for (u in f.units) {
            val dwoId = u.dwoId
                ?: u.root.num(DW.AT_GNU_dwo_id)
                ?: continue
            if (u.isSplit) splitById[dwoId] = f.id to u
        }
        for (f in all) for (u in f.units) {
            if (!u.isSkeleton) continue
            val id = u.dwoId ?: u.root.num(DW.AT_GNU_dwo_id) ?: continue
            val match = splitById[id]
            if (match != null) {
                u.linkedDwoFileId = match.first
                u.linkedDwoUnitOffset = match.second.unitOffset
            } else {
                u.issues.add(ParseIssue("warning", "cu+${u.unitOffset}",
                    "split unit '${u.dwoName() ?: u.name() ?: "?"}' (dwo_id=0x${id.toString(16)}) " +
                        "has no matching .dwo imported: inlined DIEs and split line table unavailable"))
            }
        }
        for (f in all) f.linked = true
    }
}
