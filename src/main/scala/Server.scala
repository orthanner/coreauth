import akka.actor._
import scala.concurrent.duration._
import scala.concurrent._
import akka.io._
import akka.util.ByteString
import java.net.InetSocketAddress
import org.apache.commons.dbcp2._
import java.util.concurrent.Executor
import scala.util._
import akka.util._
import java.sql.{ ResultSet, Types }
import org.apache.commons.codec.binary._
import com.typesafe.config._
import javax.sql.DataSource
import java.net._
import java.nio._
import java.nio.channels._
import java.nio.charset._
import javax.crypto._
import java.security.{ Key, PrivateKey, PublicKey, KeyFactory, Signature }
import java.security.cert._
import java.security.spec._
import java.io.{ InputStream, FileInputStream, IOException, FileNotFoundException, InputStreamReader, Reader }
import rx.lang.scala._
import rx.lang.scala.subjects._
import ExecutionContext.Implicits.global
import scala.async.Async.{ async, await }
import org.springframework.jdbc.core._
import org.springframework.jdbc.core.simple._
import org.springframework.jdbc.datasource._
import org.springframework.transaction.support._
import org.springframework.transaction._

class Server(args: scala.Array[String]) extends Actor with Loader with ActorLogging {
  import Tcp._
  import context.system

  lazy val config = ConfigFactory.parseFile(new java.io.File(if(args.length > 0) args(0) else "coreauth.conf"))
    .withFallback(ConfigFactory.parseString("udp.iface=" + NetworkInterface.getByIndex(0).getName()))
    .withFallback(ConfigFactory.parseString("udp.port=9876"))
    .withFallback(ConfigFactory.parseString("tcp.port=9876"))
    .withFallback(ConfigFactory.parseString("ssl.algorithm=RSA"))
    .withFallback(ConfigFactory.parseString("ssl.streamCipher=AES"))
    .withFallback(ConfigFactory.parseString("ssl.cipher=RSA/ECB/OAEPWithSHA-256AndMGF1Padding"))
    .withFallback(ConfigFactory.parseString("ssl.signature=SHA512withRSA"))
    .withFallback(ConfigFactory.parseString("jdbc.connLimit=16"))

  lazy val DB = {
    val db = new BasicDataSource()
    db setDriverClassName config.getString("jdbc.driver")
    db setUrl config.getString("jdbc.url")

    db setUsername config.getString("jdbc.username")
    db setPassword config.getString("jdbc.password")
    db setMaxTotal config.getInt("jdbc.connLimit")
    new JdbcTemplate(db)
  }

  lazy val keyGen = {
    val kg = KeyGenerator.getInstance(config.getString("ssl.streamCipher"))
    kg.init(256)
    kg
  }

  val cf = CertificateFactory.getInstance("X.509")

  lazy val certificate = Try {
    val in = new FileInputStream(config.getString("ssl.cert"))
    val cert = cf.generateCertificate(in)
    in.close()
    cert
  }

  lazy val key = Try {
    val in = new FileInputStream(config.getString("ssl.key"))
    val kf = KeyFactory.getInstance(config.getString("ssl.algorithm"))
    val keyData = (ByteString.empty /: (read(in) takeWhile { _._1 > 0 } map { chunk => ByteString.fromArray(chunk._2, 0, chunk._1) })) { (acc: ByteString, data: ByteString) => acc ++ data }
    in.close()
    kf.generatePrivate(new PKCS8EncodedKeySpec(keyData.toArray[Byte]))
  }

  override def preStart = {
    IO(Tcp) ! Bind(self, new InetSocketAddress(config.getInt("tcp.port")))
  }

  override def postStop = {
    IO(Tcp) ! Unbind
    context.unbecome()
  }
  
  def getInterface(name: String): Try[NetworkInterface] = Try {
    NetworkInterface.getByName(name)
  } recover {
    case e => NetworkInterface.getByInetAddress(java.net.InetAddress.getByName(name))
  } recover {
    case e => NetworkInterface.getByIndex(Integer.parseInt(name))
  }

  def receive = {
    case b @ Bound(localAddress) => {
      val announcer = certificate flatMap { cert =>
      	getInterface(config.getString("udp.iface")) map { iface =>
          context.actorOf(Props(classOf[DatagramHandler], cert, new InetSocketAddress(config.getInt("udp.port")), InetAddress.getByName(config.getString("udp.group")), iface))
        }
      }
      context.become(listening(announcer), discardOld = false)
    }
    case CommandFailed(_: Bind) => context stop self
    case _ =>
  }

  def listening(announcer: Try[ActorRef]): Receive = {
    case c @ Connected(remote, local) =>
      sender() ! Register(context.actorOf(Props(classOf[RequestHandler], remote.getHostString(), DB, key, keyGen, config)))
    case Unbind =>
      announcer match {
        case Success(ref) =>
          ref ! DatagramHandler.Unbind
        case Failure(_) =>
      }
      context.unbecome()
    case _ =>
  }

}

