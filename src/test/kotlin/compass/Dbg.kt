package compass

import compass.elf.ElfParser
import compass.dwarf.*

fun main() {
    val bytes = ScenarioFixtures.overlappingInline(4)
    val elf = ElfParser.parse(bytes)
    println("sections: " + elf.sections.joinToString { "${it.name}:${it.size}" })
    val info = DwarfParser.parse(elf, null)
    println("issues: " + info.issues.map { it.message })
    println("units: " + info.units.size)
    for (cu in info.units) {
        println("CU name=${cu.name} ver=${cu.version} issues=${cu.issues} lp=${cu.lineProgram != null}")
        fun d(die: Die, depth: Int) {
            println("  ".repeat(depth) + "tag=${die.tag.toString(16)} off=${die.globalOffset} name=${die.str(DW_AT_name)} ranges=${DieRanges.of(die)}")
            die.children.forEach { d(it, depth + 1) }
        }
        cu.root?.let { d(it, 0) }
        cu.lineProgram?.sequences?.forEachIndexed { i, s ->
            println("seq$i ${java.lang.Long.toHexString(s.start)}-${java.lang.Long.toHexString(s.end)} " +
                s.rows.joinToString { java.lang.Long.toHexString(it.address) + ":" + it.line + if (it.endSequence) "E" else "" })
        }
    }
}
