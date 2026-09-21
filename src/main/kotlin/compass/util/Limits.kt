package compass.util

/** Hard caps so a corrupt/hostile debug section cannot exhaust memory or the stack. */
object Limits {
    const val MAX_LEB128_BYTES = 16
    const val MAX_DIE_DEPTH = 128
    const val MAX_REFERENCE_HOPS = 32
    const val MAX_CU_COUNT = 100_000
    const val MAX_DIE_PER_CU = 1_000_000
    const val MAX_LINE_ROWS = 5_000_000
    const val MAX_BLOCK_BYTES = 1 shl 24
    const val MAX_TABLE_ENTRIES = 10_000_000
    const val MAX_CU_BYTES = 1L shl 32
}
