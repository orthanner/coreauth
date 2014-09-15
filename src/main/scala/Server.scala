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
import java.sql._
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
import java.io.{ InputStream, FileInputStream, IOException, FileNotFoundException }
import rx.lang.scala._
import rx.lang.scala.subjects._
import ExecutionContext.Implicits.global
import scala.async.Async.{async, await}

//case class User(id: Int, login: String, password: String)
//case class Realm(id: Int, name: String)
//case class UserAttr(user: Int, name: String, value: String)
//case class Permission(id: Int, name: String)
//case class Profile(id: Int, realm: Int, name: String)
//case class ProfileMapping(user: Int, profile: Int)
//case class PermissionMapping(profile: Int, permission: Int)
//case class Session(id: Int, user: Int, realm: Int, token: String, start: Timestamp, last: Timestamp, tag: String)

object RequestHander {
  val HANDSHAKE = "starttsl (?<cert>[\\w]+)".r
  val AUTH = "auth (?<login>[^@]+)@(?<realm>[^\\s]+) (?<password>[\\w]+)".r
  val CHECK = "check (?<token>[A-F0-9]+) (?<tag>[.:\\-\\w]+) (?<perm>[:.\\w]+)".r
  val STOP = "logout (?<token>[A-F0-9]+)".r
  val ATTR_QUERY = "get (?<token>[A-F0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_UPDATE = "set (?<token>[A-F0-9]+)/(?<attr>[\\w.\\-_:]+)=(?<value>[\\w]*|\\$)".r //$ -> delete
  val LINE_DELIMITER = Seq(13, 10)
}

case class Session(uid: Int, realm: String)

trait Loader {
  def read(fileIn: InputStream): Stream[(Int, scala.Array[Byte])] = {
    val bytes = scala.Array.fill[Byte](1024)(0)
    val length = fileIn.read(bytes)
    (length, bytes) #:: read(fileIn)
  }
}

class RequestHandler(client: String, DB: DataSource, key: PrivateKey, certificate: Option[Certificate], keyGen: KeyGenerator, config: Config) extends Actor with Loader {
  import Tcp._
  import RequestHander._
  import Crypt._
  import Base64._

  implicit val exec = context.dispatcher.asInstanceOf[Executor with ExecutionContext]

  val keyFactory = KeyFactory.getInstance(config.getString("ssl.algorithm"))

  def getSession(token: String, tag: String)(implicit conn: Connection): Option[Session] = {
    val sq = conn.prepareStatement("select uid, realm from sessions where token=? and tag=?")
    sq.setString(1, token)
    sq.setString(2, tag)
    val s = sq.executeQuery
    if (s.first()) {
      val update = conn.prepareStatement("update sessions set last=current_timestamp() where token=?")
      update.setString(1, token)
      update.executeUpdate
      Some(Session(s.getInt("uid"), s.getString("realm")))
    } else
      None
  }

  def receive = raw_receive(ByteString.empty)

  def decrypt(data: ByteString): ByteString = {
    data
  }

  def encrypt(data: ByteString, cipher: Cipher): ByteString = {
    val in = data.toByteBuffer
    val out = ByteBuffer.allocate(cipher.getOutputSize(in.limit()))
    cipher.update(in, out)
    ByteString(out)
  }

  def auth(login: String, realm: String, password: String, tag: String)(implicit conn: Connection): String = {
    val sid = generateSecureCookie
    val accountQuery = conn.prepareStatement("select id from users where lower(login)=? and password=?")
    accountQuery.setString(1, login)
    accountQuery.setString(2, password)
    val rs = accountQuery.executeQuery
    if (rs.first()) {
      val uid = rs.getInt("id")
      val realmCheck = conn.prepareStatement("select count(*)>0 from permissions p left join realms r on p.realm=r.id where p.user=? and r.name=?")
      realmCheck.setInt(1, uid)
      realmCheck.setString(2, realm)
      val rc = realmCheck.executeQuery
      if (rc.first() && rc.getBoolean(1)) {
	val insert = conn.prepareStatement("insert into sessions(uid, realm, token, start, last, tag) values(?, ?, current_date(), current_date(), ?)")
	insert.setInt(1, uid)
	insert.setString(2, sid)
	insert.setString(3, tag)
	if (insert.executeUpdate() == 0)
	  throw new SQLException("Could not create session")
      } else
	throw new java.security.AccessControlException("Specified user cannot access this realm")
    } else
      throw new java.security.AccessControlException("Invalid credentials")
    "+%s\r\n".format(sid)
  }

  def check(token: String, tag: String, permission: String)(implicit conn: Connection): String = {
    getSession(token, tag)
    val query = conn.prepareStatement("select count(*)>0 from user_permissions up left join permissions p on up.perm_id=p.id left join sessions s on s.user_id=up.user_id where s.token=? and s.tag=? and p.name=?")
    query.setString(1, token)
    query.setString(2, tag)
    query.setString(3, permission)
    val result = query.executeQuery
    if (result.first() && result.getBoolean(1)) "+\r\n" else "-\r\n"
  }

  def logout(token: String, tag: String)(implicit conn: Connection): String = {
    val query = conn.prepareStatement("delete from sessions where token=? and tag=?")
    query.setString(1, token)
    query.setString(2, tag)
    val x = query.executeUpdate
    if (x > 0) "+\r\n" else "-\r\n"
  }

  def attr_query(token: String, attr: String)(implicit conn: Connection): String = {
    val value = getSession(token, client) flatMap { session =>
	val aq = conn.prepareStatement("select value from extra_attrs where name=? and user_id=?")
	aq.setString(1, attr)
	aq.setInt(2, session.uid)
	val result = aq.executeQuery
	if (result.first())
	  Option(encodeBase64String(result.getString("value").getBytes("UTF-8")))
	else
	  None
    }
    "+%s\r\n".format(value.getOrElse("$"))
  }

  def attr_update(token: String, name: String, value: String)(implicit conn: Connection): String = {
    val result = getSession(token, client) match {
      case Some(session) => {
	if (value == "$"){
	  var aq = conn.prepareStatement("delete where user_id=? and name=?")
	  aq.setInt(1, session.uid)
	  aq.setString(2, name)
	  aq.executeUpdate
	} else { 
	  var aq = conn.prepareStatement("update extra_attrs set value=? where user_id=? and name=?")
	  aq.setString(1, ByteString(decodeBase64(value)).utf8String)
	  aq.setInt(2, session.uid)
	  aq.setString(3, name)
	  if (aq.executeUpdate == 0) {
	    aq = conn.prepareStatement("insert into extra_attrs(user_id, name, value) values (?, ?, ?)")
	    aq.setString(1, ByteString(decodeBase64(value)).utf8String)
	    aq.setInt(2, session.uid)
	    aq.setString(3, name)
	    aq.executeUpdate
	  } else
	    1
	}
      }
      case None => 0
    }
    "+%s\r\n".format(String.valueOf(result))
  }

  def raw_receive(data: ByteString): Receive = {
    case Received(input) => {
      val content = data ++ input
      val pos = content.indexOfSlice(LINE_DELIMITER)
      if (pos >= 0) {
	val msg = content.slice(0, pos)
	context become raw_receive(content.drop(msg.length + 2))
	val message = msg.utf8String.trim()
	val src = sender()
	implicit val conn = DB.getConnection
	async {
	  message match {
	    case HANDSHAKE(cert) => {
	      //generate session encryption key
	      val streamKey = keyGen.generateKey
	      //decode and parse client key
	      val clientKey = keyFactory.generatePublic(new PKCS8EncodedKeySpec(decodeBase64(cert)))
	      //encrypt session key for client...
	      val clientCipher = Cipher.getInstance(config.getString("ssl.cipher"))
	      clientCipher.init(Cipher.ENCRYPT_MODE, clientKey)
	      val keyData = clientCipher.update(streamKey.getEncoded)
	      val skey = encodeBase64(keyData)
	      //...and sign it
	      val signature = Signature.getInstance(config.getString("ssl.signature"))
	      signature.initSign(key)
	      signature.update(keyData)
	      val signatureData = encodeBase64(signature.sign())
	      //create encyption and decryption ciphers for the session
	      val encryptor = Cipher.getInstance(config.getString("ssl.streamCipher"))
	      encryptor.init(Cipher.ENCRYPT_MODE, streamKey)
	      val decryptor = Cipher.getInstance(config.getString("ssl.streamCipher"))
	      decryptor.init(Cipher.DECRYPT_MODE, streamKey)
	      //switch to TSL
	      context become crypto_receive(ByteString.empty, encryptor, decryptor, "key:%s".format(encodeBase64(clientKey.getEncoded)))
	      //send reply
	      "+%s %s\r\n".format(skey, signatureData)
	    }
	    case AUTH(login, realm, password) => auth(login, realm, password, "ip:%s".format(client))
	    case CHECK(token, tag, permission) => check(token, tag, permission)
	    case STOP(token) => logout(token, "ip:%s".format(client))
	    case ATTR_QUERY(token, attr) => attr_query(token, attr)
	    case ATTR_UPDATE(token, name, value) => attr_update(token, name, value)
	    case _ => throw new java.lang.IllegalArgumentException("Invalid request")
	  }
	} andThen {
	  case r => conn.close
	} onComplete {
	  case Success(data) => src ! Write(ByteString(data))
	  case Failure(error) => src ! Write(ByteString("-%s:%s\r\n".format(error.getClass().getName(), error.getMessage())))
	}
      } else
	context become raw_receive(content)
    }
    case PeerClosed     => context stop self
  }

  def crypto_receive(data: ByteString, encryptor: Cipher, decryptor: Cipher, pkey: String): Receive = {
    case Received(input) => {
      val content = data ++ encrypt(input, decryptor)
      val pos = content.indexOfSlice(Seq(13, 10))
      if (pos >= 0) {
	val msg = content.slice(0, pos)
	context become crypto_receive(content.drop(msg.length + 2), encryptor, decryptor, pkey)
	val message = msg.utf8String.trim()
	val src = sender()
	implicit val conn = DB.getConnection
	async {
	  message match {
	    case AUTH(login, realm, password) => auth(login, realm, password, pkey)
	    case CHECK(token, tag, permission) => check(token, tag, permission)
	    case STOP(token) => logout(token, pkey)
	    case ATTR_QUERY(token, attr) => attr_query(token, attr)
	    case ATTR_UPDATE(token, name, value) => attr_update(token, name, value)
	    case _ => throw new java.lang.IllegalArgumentException("Invalid request")
	  }
	} andThen {
	  case r => conn.close()
	} onComplete {
	  case Success(data) => src ! Write(encrypt(ByteString(data), encryptor))
	  case Failure(error) => src ! Write(encrypt(ByteString("-%s:%s\r\n".format(error.getClass().getName(), error.getMessage())), encryptor))
	}
      } else
	context become crypto_receive(content, encryptor, decryptor, pkey)
    }
    case PeerClosed     => context stop self
  }

}

class Server(args: scala.Array[String]) extends Actor with Loader {
  import Tcp._
  import context.system

  lazy val config = ConfigFactory.parseFile(new java.io.File(if(args.length > 0) args(0) else "coreauth.conf"))
    .withFallback(ConfigFactory.parseString("udp.interface=" + NetworkInterface.getByIndex(0).getName()))
    .withFallback(ConfigFactory.parseString("udp.port=9876"))
    .withFallback(ConfigFactory.parseString("tcp.port=9876"))
    .withFallback(ConfigFactory.parseString("ssl.algorithm=RSA"))
    .withFallback(ConfigFactory.parseString("ssl.streamCipher=AES"))
    .withFallback(ConfigFactory.parseString("ssl.cipher=RSA/ECB/OAEPWithSHA-256AndMGF1Padding"))
    .withFallback(ConfigFactory.parseString("ssl.signature=SHA512withRSA"))

  lazy val DB = {
    val db = new BasicDataSource()
    db setDriverClassName config.getString("jdbc.driver")
    db setUrl config.getString("jdbc.url")

    db setUsername config.getString("jdbc.username")
    db setPassword config.getString("jdbc.password")
    db setMaxTotal config.getInt("jdbc.connLimit")
    db
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
  } toOption

  lazy val key = Try {
    val in = new FileInputStream(config.getString("ssl.key"))
    val kf = KeyFactory.getInstance(config.getString("ssl.algorithm"))
    val keyData = (ByteString.empty /: (read(in) takeWhile { _._1 > 0 } map { chunk => ByteString.fromArray(chunk._2, 0, chunk._1) })) { (acc: ByteString, data: ByteString) => acc ++ data }
    kf.generatePrivate(new PKCS8EncodedKeySpec(keyData.toArray[Byte]))
  } toOption

  override def preStart = {
    IO(Tcp) ! Bind(self, new InetSocketAddress(config.getInt("tcp.port")))
  }

  override def postStop = {
    IO(Tcp) ! Unbind
    context become receive
  }
  
  def receive = {
    case b @ Bound(localAddress) => {
      val announcer = certificate map { cert =>
        context.actorOf(Props(classOf[DatagramHandler], cert, new InetSocketAddress(config.getInt("udp.port")), InetAddress.getByName(config.getString("udp.group")), NetworkInterface.getByName(config.getString("udp.interface"))))
      }
      context.become(listening(announcer), discardOld = false)
    }
    case CommandFailed(_: Bind) => context stop self
    case _ =>
  }

  def listening(announcer: Option[ActorRef]): Receive = {
    case c @ Connected(remote, local) =>
      sender() ! Register(context.actorOf(Props(classOf[RequestHandler], remote.getHostString(), DB, key, certificate, keyGen, config)))
    case Unbind =>
      announcer match {
        case Some(ref) =>
          ref ! PoisonPill
        case None =>
      }
      context.unbecome()
    case _ =>
  }

}

