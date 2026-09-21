package compass

import compass.dwarf.ParsedDwarf
import compass.elf.ElfFile
import compass.resolve.AddressEngine
import compass.store.LoadedModule

internal fun testEngine(dwarf: ParsedDwarf, elf: ElfFile? = null): AddressEngine {
    val mod = LoadedModule(
        id = 1, key = "testmod", version = 1, fileName = "test.elf",
        sha256 = "test", elf = elf ?: ElfFile(
            ByteArray(0), 2, 1, 62, 2, 0, emptyList(), emptyList(), ByteArray(0),
        ),
        dwarf = dwarf, importedAt = "now", superseded = false,
    )
    return AddressEngine(mod)
}
