import java.io._

trait Loader {
  def read(in: InputStream): Stream[(Int, Array[Byte])] = {
    val bytes = scala.Array.fill[Byte](1024)(0)
    val length = in.read(bytes)
    (length, bytes.slice(0, length)) #:: read(in)
  }

  def read(in: Reader): Stream[(Int, Array[Char])] = {
    val buf = scala.Array.fill[Char](1024)(0)
    val length = in.read(buf)
    (length, buf.slice(0, length)) #:: read(in)
  }
}
