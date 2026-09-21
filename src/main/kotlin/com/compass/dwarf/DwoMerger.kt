package com.compass.dwarf

/**
 * Merges skeleton CUs (main executable) with split CUs (.dwo) by
 * DW_AT_dwo_id. The skeleton keeps its line program; the dwo contributes the
 * inline DIE tree. A missing dwo leaves the skeleton unresolved so queries can
 * state which conclusions remain trustworthy.
 */
object DwoMerger {
    private const val DWO_MARKER = 0x4000_0000

    fun merge(main: ParsedDebug, dwos: List<ParsedDebug>): ParsedDebug {
        val dwoIndex = HashMap<Long, CuInfo>()
        for (dwo in dwos) for (cu in dwo.cus) {
            cu.dwoId?.let { dwoIndex.putIfAbsent(it, cu) }
        }
        val mergedCus = main.cus.map { skel ->
            val dwoCu = skel.dwoId?.let { dwoIndex[it] }
            if (dwoCu == null) {
                skel.issues += ParseIssue("split-dwarf", "dwo_id=0x${skel.dwoId?.toString(16)} 未找到匹配的 .dwo 文件", "warn")
                // Re-tag as an unresolved split unit so queries explain that
                // line/range results hold but the inline tree may be partial.
                CuInfo(skel.offset, skel.version, skel.dwarf64, skel.unitType,
                    isSplit = true, dwoId = skel.dwoId, compDir = skel.compDir,
                    name = skel.name, lowPc = skel.lowPc, ranges = skel.ranges,
                    dies = skel.dies, lineTable = skel.lineTable, issues = skel.issues,
                    dwoResolved = false)
            } else {
                mergeOne(skel, dwoCu)
            }
        }
        return ParsedDebug(
            main.elf, mergedCus, main.issues + dwos.flatMap { it.issues },
            main.sectionsParsed + dwos.flatMap { it.sectionsParsed },
            isDwo = false,
            dwoIds = main.dwoIds + dwos.flatMap { it.dwoIds }
        )
    }

    private fun mark(off: Int) = off or DWO_MARKER

    private fun mergeOne(skel: CuInfo, dwoCu: CuInfo): CuInfo {
        // Remap dwo offsets into a disjoint number space; attach dwo root's
        // children directly beneath the skeleton root.
        val rootOff = skel.offset.toInt()
        val dwoRoot = dwoCu.dies.firstOrNull()
        val joined = skel.dies.toMutableList()
        for (d in dwoCu.dies) {
            if (d === dwoRoot) continue
            val parent = when (d.parentOffset) {
                -1 -> rootOff
                dwoRoot?.offset -> rootOff
                else -> mark(d.parentOffset)
            }
            joined += DieRecord(
                mark(d.offset), d.tag, parent, d.depth,
                d.attrs, d.ranges, d.resolvedName, d.linkageName, d.callFileResolved
            )
        }
        val issues = (skel.issues + dwoCu.issues).toMutableList()
        return CuInfo(
            skel.offset, skel.version, skel.dwarf64, skel.unitType, isSplit = true,
            dwoId = skel.dwoId,
            compDir = dwoCu.compDir ?: skel.compDir,
            name = dwoCu.name ?: skel.name,
            lowPc = skel.lowPc ?: dwoCu.lowPc,
            ranges = mergeRanges(skel.ranges, dwoCu.ranges),
            dies = joined,
            lineTable = skel.lineTable ?: dwoCu.lineTable,
            issues = issues,
            dwoResolved = true
        )
    }

    private fun mergeRanges(a: List<AddrRange>, b: List<AddrRange>): List<AddrRange> {
        val out = (a + b).distinct().toMutableList()
        return out.sortedWith(compareBy({ it.low }, { it.high }))
    }
}

/** First/last bytes + size + sha256 summary, persisted for auditability. */
data class ByteSummary(val size: Int, val sha256: String, val head16: String, val tail16: String) {
    fun serial() = mapOf("size" to size, "sha256" to sha256, "head16" to head16, "tail16" to tail16)
}

object ByteDigest {
    fun summary(bytes: ByteArray): ByteSummary {
        val md = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        fun hex(arr: ByteArray) = arr.joinToString("") { "%02x".format(it) }
        val headLen = minOf(16, bytes.size)
        val tailStart = (bytes.size - 16).coerceAtLeast(0)
        return ByteSummary(
            bytes.size,
            md.joinToString("") { "%02x".format(it) },
            hex(bytes.copyOfRange(0, headLen)),
            hex(bytes.copyOfRange(tailStart, bytes.size))
        )
    }
}
