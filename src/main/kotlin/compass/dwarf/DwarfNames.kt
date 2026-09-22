package compass.dwarf

/**
 * Name resolution incl. abstract_origin / specification chains.
 * Reference hops are capped ([Limits.MAX_REF_HOPS]); local refs are
 * unitStart-relative, global refs are section offsets.
 */
class DwarfNames(private val resolveGlobal: (Long, Long) -> DieNode?) {

    fun name(d: DieNode, unit: CompUnit): String? {
        var node: DieNode? = d
        var curUnit = unit
        var hops = 0
        while (node != null) {
            directName(node)?.let { return it }
            val ref = node.attr(DW.AT_abstract_origin)?.value
                ?: node.attr(DW.AT_specification)?.value
            if (ref is FormValue.Reference && ref.kind != RefKind.TYPE_SIGNATURE) {
                if (++hops > Limits.MAX_REF_HOPS) return "<ref-chain-too-long>"
                val target = when (ref.kind) {
                    RefKind.LOCAL_INFO -> curUnit.findDie(curUnit.unitOffset + ref.offset)
                    RefKind.GLOBAL_INFO -> resolveGlobal(curUnit.fileId, ref.offset)
                    RefKind.EXTERNAL_SUP -> null
                    RefKind.TYPE_SIGNATURE -> null
                }
                if (target == null) return "<unresolved-origin>"
                node = target
                continue
            }
            return null
        }
        return null
    }

    private fun directName(die: DieNode): String? {
        (die.attr(DW.AT_name)?.value as? FormValue.Text)?.let { return it.value }
        (die.attr(DW.AT_linkage_name)?.value as? FormValue.Text)?.let { return it.value }
        (die.attr(DW.AT_MIPS_linkage_name)?.value as? FormValue.Text)?.let { return it.value }
        return null
    }
}
