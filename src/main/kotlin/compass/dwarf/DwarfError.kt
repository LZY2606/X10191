package compass.dwarf

open class DwarfError(message: String) : Exception(message)

/** Section 游标越界、长度字段损坏等。 */
class CursorError(message: String) : DwarfError(message)

/** 未知 DWARF form：必须隔离当前 DIE/CU，绝不允许猜测长度导致游标错位。 */
class UnknownFormError(val form: Int, message: String) : DwarfError(message)

/** 引用跳转越界（ref / strp / sec_offset 指向 section 之外）。 */
class BadReferenceError(message: String) : DwarfError(message)

/** 超过递归 / 长度 / 数量限制。 */
class LimitExceededError(message: String) : DwarfError(message)
