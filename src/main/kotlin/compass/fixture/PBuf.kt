package compass.fixture

import java.io.ByteArrayOutputStream

/** ByteArrayOutputStream with public access to its backing buffer. */
class PBuf : ByteArrayOutputStream() {
    public override fun toString(): String = super.toString()
    val buf: ByteArray get() = super.buf
}
