import scala.util._
import akka.util._
import akka.actor._
import java.net._
import java.nio._
import java.nio.channels._
import javax.crypto._
import java.security.{ Key, PublicKey, PrivateKey, KeyFactory }
import java.security.cert._
import java.security.spec._
import java.util.concurrent._
import java.util.concurrent.atomic._
import java.util.concurrent.locks._
import java.io._

object DatagramHandler {
  sealed class Message
  case class Datagram(data: ByteString, address: SocketAddress) extends Message
  case class Bind(handler: ActorRef, bindAddr: InetSocketAddress, group: InetAddress, iface: NetworkInterface) extends Message
  case object Unbind extends Message
  case object Bound extends Message
  case object Unbound extends Message
}

class DatagramProcessor(certificate: Certificate) extends Actor {
  import DatagramHandler._

  val cf = CertificateFactory.getInstance("X.509")

  def receive = {
    case d @ Datagram(data, client) => {
      val in = new ByteArrayInputStream(data.toArray[Byte])
      val submittedCertificate = cf.generateCertificate(in)
      in.close()
      if (certificate.equals(submittedCertificate))
	context.parent ! d
    }
    case Unbind => context stop self
  }
}

class DatagramHandler(certificate: Certificate, bindAddr: InetSocketAddress, group: InetAddress, iface: NetworkInterface) extends Actor with Runnable {
  import DatagramHandler._

  val alive = new AtomicBoolean()
  val pending = new ConcurrentLinkedQueue[Datagram]()
  var runner: Thread = null
  val processor = context.actorOf(Props(classOf[DatagramProcessor], certificate))

  override def preStart(): Unit = {
    runner = new Thread(this)
    alive.set(true)
    runner.start()
  }

  override def postStop(): Unit = {
    runner = null
  }

  def receive = {
    case datagram: Datagram =>
      pending.add(datagram)
    case Unbind => alive.set(false)
  }

  override def run(): Unit = {
    var channel = DatagramChannel.open.setOption[java.lang.Boolean](StandardSocketOptions.SO_REUSEADDR, true).bind(bindAddr)
    channel.configureBlocking(false)
    val key = channel.join(group, iface)
    val buffer = ByteBuffer.allocate(1024)
    val selector = Selector.open
    val membership = channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, null)
    while (alive.get) {
      if (selector.selectNow() > 0) {
	if ((membership.readyOps() | SelectionKey.OP_READ) != 0) {
	  channel.receive(buffer) match {
            case client: SocketAddress => {
	      buffer.flip()
	      processor ! Datagram(ByteString(buffer), client)
	      buffer.clear()
	    }
            case null =>
	  }
	}
	if ((membership.readyOps() | SelectionKey.OP_WRITE) != 0) {
	  pending.poll() match {
	    case Datagram(data, client) => {
	      channel.send(data.toByteBuffer, client)
	    }
	    case null =>
	  }
	}
      }
      Thread.`yield`()
    }
    processor ! Unbind
    key.drop
    channel.close
    context stop self
  }

}
