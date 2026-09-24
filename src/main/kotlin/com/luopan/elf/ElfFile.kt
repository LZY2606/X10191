package com.luopan.elf

import com.luopan.dwarf.Binary
import com.luopan.dwarf.DwarfReadException
import com.luopan.dwarf.Endian

/** 一个 ELF section 的描述与（可能已被重定位修正的）原始字节。 */
class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
    val bytes: ByteArray,
)

class ElfProgramHeader(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

/** 原始字节摘要：导入时保存，供版本对比与完整性展示。 */
class ByteDigest(val sha256: String, val size: Long, val first16Hex: String)

/** 解析结果。diagnostics 是非致命问题；致命问题直接抛出。 */
class ElfImage(
    val elfClass: Int,
    val endian: Endian,
    val machine: Int,
    val type: Int,
    val sections: List<ElfSection>,
    val programHeaders: List<ElfProgramHeader>,
    val buildId: String?,
    val entry: Long,
    val isRelocatable: Boolean,
    val diagnostics: MutableList<String>,
    val sectionByName: Map<String, ElfSection>,
    val digest: ByteDigest,
) {
    fun section(name: String): ElfSection? = sectionByName[name]

    /**
     * 可执行/共享对象的首选加载基址：取第一个 PT_LOAD 段 vaddr。
     * 运行时 load bias = 实际映射基址 - 首选基址。
     */
    val preferredLoadBase: Long
        get() = programHeaders.filter { it.type == PT_LOAD }.minByOrNull { it.vaddr }?.vaddr ?: 0L

    companion object {
        const val PT_LOAD = 1
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
    }
}
