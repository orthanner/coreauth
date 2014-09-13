import scala.concurrent.duration._
import scala.concurrent._
import java.util.concurrent.Executor
import scala.util._
import akka.util._
import java.sql._
import org.apache.commons.codec.binary._
import java.net._
import java.nio._
import java.nio.channels._
import java.nio.charset._
import javax.crypto._
import java.security.{ Key, PublicKey, PrivateKey, KeyFactory }
import java.security.cert._
import java.security.spec._
import java.io.{ InputStream, FileInputStream, IOException, FileNotFoundException }
import java.util.concurrent._
import java.util.concurrent.atomic._
import java.util.concurrent.locks._

case class Data(source: SocketAddress, data: List[Byte])

class DatagramHandler(val channel: DatagramChannel, certificate: Certificate) extends Thread {

  val alive = new AtomicBoolean()
  val buffer = ByteBuffer.allocate(1024)
  var pending = Map[SocketAddress, scala.Array[Byte]]()

  override def run(): Unit = {
    while(alive.get) {
      Option(channel.receive(buffer)) match {
	case Some(client) => {
	  
	}
	case None =>
      }
    }
  }
  
}