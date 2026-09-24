package parser

data class DwarfSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val str: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val addr: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rngLists: ByteArray? = null,
    val locLists: ByteArray? = null,
    val infoDwo: ByteArray? = null,
    val abbrevDwo: ByteArray? = null,
    val strDwo: ByteArray? = null,
    val strOffsetsDwo: ByteArray? = null,
    val lineDwo: ByteArray? = null,
    val rngListsDwo: ByteArray? = null,
    val locListsDwo: ByteArray? = null,
    val dwoPresent: Boolean = false,
    val dwoName: String? = null,
)
