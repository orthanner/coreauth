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

class DatagramHandler(certificate: Certificate, bindAddr: InetSocketAddress, group: InetAddress, iface: NetworkInterface) extends Thread {

  val alive = new AtomicBoolean()
  var pending = Map[SocketAddress, scala.Array[Byte]]()
  //val selector = Selector.open

  def run(): Unit = {
    var channel = DatagramChannel.open.setOption[java.lang.Boolean](StandardSocketOptions.SO_REUSEADDR, true).bind(bindAddr)
    channel.configureBlocking(false)
    val key = channel.join(group, iface)
    //selector.register(channel, SelectionKey.OP_READ | SelectionKey.OP_WRITE)
    val buffer = ByteBuffer.allocate(1024)
    while(alive.get) {
      Option(channel.receive(buffer)) match {
        case Some(client) =>
        case None =>
      }
      `yield`()
    }
    key.drop
    channel.close
  }

}
