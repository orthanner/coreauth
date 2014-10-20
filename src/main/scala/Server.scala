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
import java.io.{ InputStream, FileInputStream, IOException, FileNotFoundException, InputStreamReader, Reader }
import rx.lang.scala._
import rx.lang.scala.subjects._
import ExecutionContext.Implicits.global
import scala.async.Async.{ async, await }

object RequestHander {
  val HANDSHAKE = "starttls (?<cert>[\\w]+)".r
  val AUTH = "auth (?<login>[^@]+)@(?<realm>[^\\s]+) (?<password>[\\w]+)".r
  val CHECK = "check (?<token>[A-Fa-f0-9]+) (?<tag>[.:\\-\\w]+) (?<perm>[:.\\w]+)".r
  val STOP = "logout (?<token>[A-Fa-f0-9]+)".r
  val ATTR_QUERY = "get (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_QUERY_EXTERNAL = "get (?<token>[A-Fa-f0-9]+)@(?<tag>(?:ip|key):[^/]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_UPDATE = "set (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)=(?<value>[\\w]*|\\$)".r //$ -> null
  val ATTR_DELETE = "unset (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val LINE_DELIMITER = Seq(13, 10)
}

case class Session(uid: Int, realm: String)

trait Loader {
  def read(in: InputStream): Stream[(Int, scala.Array[Byte])] = {
    val bytes = scala.Array.fill[Byte](1024)(0)
    val length = in.read(bytes)
    (length, bytes.slice(0, length)) #:: read(in)
  }

  def read(in: Reader): Stream[(Int, scala.Array[Char])] = {
    val buf = scala.Array.fill[Char](1024)(0)
    val length = in.read(buf)
    (length, buf.slice(0, length)) #:: read(in)
  }
}

class RequestHandler(client: String, DB: DataSource, key: Try[PrivateKey], keyGen: KeyGenerator, config: Config) extends Actor with Loader with ActorLogging {
  import Tcp._
  import RequestHander._
  import Crypt._
  import Base64._

  implicit val exec = context.dispatcher.asInstanceOf[Executor with ExecutionContext]

  val keyFactory = KeyFactory.getInstance(config.getString("ssl.algorithm"))

  def getSession(token: String, tag: String)(implicit conn: Connection): Option[Session] = {
    val sq = conn.prepareStatement("select user_id, realm from session where token=? and tag=?")
    sq.setString(1, token)
    sq.setString(2, tag)
    val s = sq.executeQuery
    if (s.first()) {
      val update = conn.prepareStatement("update session set last=current_timestamp() where token=?")
      update.setString(1, token)
      update.executeUpdate
      Some(Session(s.getInt("user_id"), s.getString("realm")))
    } else
      None
  }

  def receive = raw_receive(ByteString.empty)

  def encrypt(data: ByteString, cipher: Cipher): ByteString = {
    val in = data.toByteBuffer
    val out = ByteBuffer.allocate(cipher.getOutputSize(in.limit()))
    cipher.update(in, out)
    ByteString(out)
  }

  def auth(login: String, realm: String, password: String, tag: String)(implicit conn: Connection): String = {
    val sid = generateSecureCookie
    val accountQuery = conn.prepareStatement("select id from users where lower(login)=lower(?) and password=?")
    accountQuery.setString(1, login)
    accountQuery.setString(2, password)
    val rs = accountQuery.executeQuery
    if (rs.first()) {
      val uid = rs.getInt("id")
      val realmCheck = conn.prepareStatement("select count(*)>0 from profile_permissions pp left join profile p on pp.profile=p.id left join user_profile up on p.id=up.profile_id where up.user_id=? and p.realm=?")
      realmCheck.setInt(1, uid)
      realmCheck.setString(2, realm)
      val rc = realmCheck.executeQuery
      if (rc.first() && rc.getBoolean(1)) {
      	val insert = conn.prepareStatement("insert into session(uid, realm, token, tag) values(?, ?, ?, ?)")
      	insert.setInt(1, uid)
      	insert.setString(2, realm)
      	insert.setString(3, sid)
      	insert.setString(4, tag)
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
    val query = conn.prepareStatement("select count(*)>0 from profile_permissions pp left join profile p on pp.profile=p.id left join permission perm on pp.permission=perm.id left join user_profile up on p.id=up.profile_id left join session s on s.user_id=up.user_id where s.token=? and s.tag=? and perm.name=?")
    query.setString(1, token)
    query.setString(2, tag)
    query.setString(3, permission)
    val result = query.executeQuery
    if (result.first() && result.getBoolean(1)) "+\r\n" else "-\r\n"
  }

  def logout(token: String, tag: String)(implicit conn: Connection): String = {
    val query = conn.prepareStatement("delete from session where token=? and tag=?")
    query.setString(1, token)
    query.setString(2, tag)
    val x = query.executeUpdate
    if (x > 0) "+\r\n" else "-\r\n"
  }

  def attr_query(token: String, tag: String, attr: String)(implicit conn: Connection): String = {
    getSession(token, tag) map { session =>
    	val aq = conn.prepareStatement("select \"type\", value from extra_attrs where name=? and user_id=?")
    	aq.setString(1, attr)
    	aq.setInt(2, session.uid)
    	val result = aq.executeQuery
    	if (result.first()) {
        val in = result.getCharacterStream("value")
        val sb = ((new StringBuilder()) /: (read(in) takeWhile { _._1 != -1 } map { _._2 })) (_.append(_))
        in.close()
        val t = result.getString("type")
        val value = t match {
          case "text" => ByteString(encodeBase64String(sb.toString.getBytes("UTF-8")))
          case _ => sb.toString
        }
    	  "%s:%s".format(t, value)
      }
    	else
    	  "$"
    } match {
      case Some(v) => "+%s\r\n".format(v)
      case None => "-\r\n"
    }
  }

  def attr_update(token: String, tag: String, name: String, t: String, value: String)(implicit conn: Connection): String = {
    getSession(token, tag) match {
      case Some(session) => {
        var aq = conn.prepareStatement("update extra_attrs set value=?, type=? where user_id=? and name=?")
        val clob = conn.createClob
        clob.setString(1, t match {
            case "text" => ByteString(decodeBase64(value)).utf8String
            case _ => value
        })
        aq.setClob(1, clob)
        aq.setString(2, t)
        aq.setInt(3, session.uid)
        aq.setString(4, name)
        val result = if (aq.executeUpdate == 0) {
          aq = conn.prepareStatement("insert into extra_attrs(user_id, name, type, value) values (?, ?, ?, ?)")
        val clob = conn.createClob
        clob.setString(1, t match {
            case "text" => ByteString(decodeBase64(value)).utf8String
            case _ => value
        })
        aq.setInt(1, session.uid)
        aq.setString(2, name)
        aq.setString(3, t)
        aq.setClob(4, clob)
        aq.executeUpdate
        } else
          1
        "+%s\r\n".format(String.valueOf(result))
      }
      case None => "-\r\n"
    }
    
  }

  def attr_delete(token: String, tag: String, name: String)(implicit conn: Connection): String = {
    getSession(token, tag) match {
      case Some(session) => {
        var aq = conn.prepareStatement("delete from extra_attrs where user_id=? and name=?")
        aq.setInt(1, session.uid)
        aq.setString(2, name)
        "+%s\r\n".format(String.valueOf(aq.executeUpdate))
      }
      case None => "-\r\n"
    }
  }

  def raw_receive(data: ByteString): Receive = {
    case Received(input) => {
      val content = data ++ input
      val pos = content.indexOfSlice(LINE_DELIMITER)
      if (pos >= 0) {
        	val msg = content.slice(0, pos)
        	context become raw_receive(content.drop(msg.length + LINE_DELIMITER.size))
        	val message = msg.utf8String.trim()
        	val src = sender()
        	implicit val conn = DB.getConnection
        	async {
        	  message match {
        	    case HANDSHAKE(cert) => {
        	      key match {
              		case Success(k) => {
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
              		  signature.initSign(k)
              		  signature.update(keyData)
              		  val signatureData = encodeBase64(signature.sign())
              		  //create encyption and decryption ciphers for the session
              		  val encryptor = Cipher.getInstance(config.getString("ssl.streamCipher"))
              		  encryptor.init(Cipher.ENCRYPT_MODE, streamKey)
              		  val decryptor = Cipher.getInstance(config.getString("ssl.streamCipher"))
              		  decryptor.init(Cipher.DECRYPT_MODE, streamKey)
              		  //switch to TLS
              		  context become crypto_receive(ByteString.empty, encryptor, decryptor, "key:%s".format(encodeBase64(clientKey.getEncoded)))
              		  //send reply
              		  "+%s %s\r\n".format(skey, signatureData)
              		}
              		case Failure(error) => {
              		  log.error("Failed to load key", error)
              		  "-%s: %s\r\n".format(error.getClass().getName(), error.getMessage())
              		}
      	      }
      	    }
      	    case AUTH(login, realm, password) => auth(login, realm, password, "ip:%s".format(client))
      	    case CHECK(token, tag, permission) => check(token, tag, permission)
      	    case STOP(token) => logout(token, "ip:%s".format(client))
            case ATTR_QUERY(token, attr) => attr_query(token, "ip:%s".format(client), attr)
      	    case ATTR_QUERY_EXTERNAL(token, tag, attr) => attr_query(token, tag, attr)
      	    case ATTR_UPDATE(token, name, t, value) => attr_update(token, "ip:%s".format(client), name, t, value)
            case ATTR_DELETE(token, attr) => attr_delete(token, "ip:%s".format(client), attr)
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
      val pos = content.indexOfSlice(LINE_DELIMITER)
      if (pos >= 0) {
      	val msg = content.slice(0, pos)
      	context become crypto_receive(content.drop(msg.length + LINE_DELIMITER.size), encryptor, decryptor, pkey)
      	val message = msg.utf8String.trim()
      	val src = sender()
      	implicit val conn = DB.getConnection
      	async {
      	  message match {
      	    case AUTH(login, realm, password) => auth(login, realm, password, pkey)
      	    case CHECK(token, tag, permission) => check(token, tag, permission)
      	    case STOP(token) => logout(token, pkey)
      	    case ATTR_QUERY(token, attr) => attr_query(token, pkey, attr)
      	    case ATTR_QUERY_EXTERNAL(token, tag, attr) => attr_query(token, tag, attr)
      	    case ATTR_UPDATE(token, name, t, value) => attr_update(token, pkey, name, t, value)
            case ATTR_DELETE(token, attr) => attr_delete(token, pkey, attr)
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

