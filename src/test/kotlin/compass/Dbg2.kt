package compass
import compass.elf.*
import compass.dwarf.*
fun main() {
  for (v in listOf(4,5)) {
    val elf = ElfParser.parse(ScenarioFixtures.overlappingInline(v))
    val lp = LinePrograms.parse(DebugSections.fromElf(elf), CuInfo(version=v, addressSize=8), 0)
    println("v$v seqs=${lp?.sequences?.size}")
    lp?.sequences?.forEachIndexed { i,s -> println(" seq$i " + s.rows.joinToString { java.lang.Long.toHexString(it.address)+":"+it.line+if(it.endSequence)"E" else "" }) }
  }
}
