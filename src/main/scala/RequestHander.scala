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
import java.sql.{ ResultSet, Types, SQLException }
import org.apache.commons.codec.binary._
import com.typesafe.config._
import javax.sql.DataSource
import java.net._
import java.nio._
import java.nio.channels._
import java.nio.charset._
import javax.crypto._
import java.security.{ Key, PrivateKey, PublicKey, KeyFactory, Signature, AccessControlException }
import java.security.cert._
import java.security.spec._
import java.io.{ InputStream, FileInputStream, IOException, FileNotFoundException, InputStreamReader, Reader }
import rx.lang.scala._
import rx.lang.scala.subjects._
import ExecutionContext.Implicits.global
import scala.async.Async.{ async, await }
import org.springframework.jdbc.core._
import org.springframework.jdbc.core.simple._
import org.springframework.jdbc.core.support._
import org.springframework.jdbc.datasource._
import org.springframework.transaction.support._
import org.springframework.transaction._
import scala.language.postfixOps
import collection.JavaConverters._

case class Session(uid: Int, realm: String)

object RequestHander {
  val HANDSHAKE = "starttls (?<cert>[\\w]+)".r
  val AUTH = "auth (?<login>[^@]+)@(?<realm>[^\\s]+) (?<password>[\\w]+)".r
  val CHECK = "check (?<token>[A-Fa-f0-9]+) (?<tag>[.:\\-\\w]+) (?<perm>[:.\\w]+)".r
  val STOP = "logout (?<token>[A-Fa-f0-9]+)".r
  val ATTR_QUERY = "get (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_QUERY_EXTERNAL = "get (?<token>[A-Fa-f0-9]+)@(?<tag>(?:ip|key):[^/]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_UPDATE = "set (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)=(?<type>[\\w]+):(?<value>[\\w]*|\\$)".r //$ -> null
  val ATTR_DELETE = "unset (?<token>[A-Fa-f0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val LINE_DELIMITER = Seq(13, 10)
}

class RequestHandler(client: String, DB: JdbcTemplate, key: Try[PrivateKey], keyGen: KeyGenerator, config: Config) extends Actor with Loader with ActorLogging with TxHelpers with JdbcHelpers {
  import Tcp._
  import RequestHander._
  import Crypt._
  import Base64._

  implicit val exec = context.dispatcher.asInstanceOf[Executor with ExecutionContext]

  val sessionStarter = new SimpleJdbcInsert(DB).withTableName("session").usingColumns("user_id", "realm", "token", "tag")

  val keyFactory = KeyFactory.getInstance(config.getString("ssl.algorithm"))

  def getSession(token: String, tag: String): Option[Session] =
    get(DB)("select user_id, realm from session where token=? and tag=?", token, tag) { s =>
      Session(s.getInt("user_id"), s.getString("realm"))
    }

  def receive = raw_receive(ByteString.empty)

  def encrypt(data: ByteString, cipher: Cipher): ByteString = {
    val in = data.toByteBuffer
    val out = ByteBuffer.allocate(cipher.getOutputSize(in.limit()))
    cipher.update(in, out)
    ByteString(out)
  }

  def auth(login: String, realm: String, password: String, tag: String): Option[String] = {
    val sid = generateSecureCookie
    get(DB)("select id from users where lower(login)=lower(?) and password=?", login, password) { rs =>
      rs.getInt("id")
    } flatMap { uid =>
      get(DB)("select count(*)>0 from profile_permissions pp left join profile p on pp.profile=p.id left join user_profile up on p.id=up.profile_id where up.user_id=? and p.realm=?", uid.asInstanceOf[Object], realm) {
        (rc: ResultSet) => (uid, rc.getBoolean(1))
      }
    } match {
      case None => throw new AccessControlException("Invalid credentials")
      case Some(t) => t match {
        case (uid: Int, permitted: Boolean) =>
          if (permitted) {
            if (sessionStarter.execute(Map("user_id" -> uid, "realm" -> realm, "token" -> sid, "tag" -> tag) map { case (k, v) => (k, v.asInstanceOf[Object]) } asJava) == 0)
              throw new SQLException("Could not create session")
            else
              Some(sid)
          } else {
            throw new AccessControlException("Specified user cannot access this realm")
          }
      }
    }
  }

  def check(token: String, tag: String, permission: String): Option[String] =
    get(DB)("select count(*)>0 from profile_permissions pp left join profile p on pp.profile=p.id left join permission perm on pp.permission=perm.id left join user_profile up on p.id=up.profile_id left join session s on s.user_id=up.user_id where s.token=? and s.tag=? and perm.name=?", token, tag, permission) { rs =>
      if (rs.getBoolean(1)) "ok" else throw new java.security.AccessControlException("Current user may not perform this operation")
    }

  def logout(token: String, tag: String): Option[String] = if (update(DB)("delete from session where token=? and tag=?")(token, tag) > 0) Some("bye") else throw new NullPointerException("session not found")

  def attr_query(token: String, tag: String, attr: String): Option[String] =
    getSession(token, tag) map { session =>
      attr match {
        case "login" => get(DB)("select login from users where id=?", session.uid.asInstanceOf[Object]) { result =>
          "text:%s".format(encodeBase64String(result.getString("login").getBytes("UTF-8")))
        } get
        case _ => get(DB)("select \"type\", value from extra_attrs where name=? and user_id=?", attr, session.uid.asInstanceOf[Object]) { result =>
          val in = result.getCharacterStream("value")
          val sb = new String((Array.empty[Char] /: (read(in) takeWhile { _._1 != -1 } map { _._2 } )) (_ ++ _))
          in.close()
          val t = result.getString("type")
          val value = t match {
            case "text" => encodeBase64String(sb.getBytes("UTF-8"))
            case _ => sb
          }
          log.info("attr value for {}/{}/{} is {}", token, tag, attr, value)
          "%s:%s".format(t, value)
        } getOrElse "$"
      }
    }

  def attr_update(token: String, tag: String, name: String, t: String, value: String): Option[String] =
    getSession(token, tag) map { session =>
      val clob = new SqlLobValue(if ("text".compareTo(t) == 0) ByteString(decodeBase64(value)).utf8String else value)
      val changed = DB.update("update extra_attrs set value=?, \"type\"=? where user_id=? and name=?", clob, t, session.uid.asInstanceOf[Object], name)
      if (changed == 0) {
        DB.update("insert into extra_attrs(value, \"type\", user_id, name, type, value) values (?, ?, ?, ?)", clob, t, session.uid.asInstanceOf[Object], name)
      } else
        changed
    } map { String.valueOf(_) }

  def attr_delete(token: String, tag: String, name: String): Option[String] =
    getSession(token, tag) map { session =>
      DB.update("delete from extra_attrs where user_id=? and name=?", session.uid.asInstanceOf[Object], name)
    } map { String.valueOf(_) }

  def raw_receive(data: ByteString): Receive = {
    case Received(input) => {
      val content = data ++ input
      val pos = content.indexOfSlice(LINE_DELIMITER)
      if (pos >= 0) {
        	val msg = content.slice(0, pos)
        	context become raw_receive(content.drop(msg.length + LINE_DELIMITER.size))
        	val message = msg.utf8String.trim()
        	val src = sender()
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
              		  Some("%s %s".format(skey, signatureData))
              		}
              		case Failure(error) => {
              		  log.error("Failed to load key", error)
              		  throw error
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
      	} onComplete {
      	  case Success(result) => result match {
            case Some(data) => src ! Write(ByteString("+%s\r\n".format(data)))
            case None => src ! Write(ByteString("-no session found\r\n"))
          }
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
      	} onComplete {
          case Success(result) => result match {
            case Some(data) => src ! Write(encrypt(ByteString("+%s\r\n".format(data)), encryptor))
            case None => src ! Write(encrypt(ByteString("-no session found\r\n"), encryptor))
          }
      	  case Failure(error) => src ! Write(encrypt(ByteString("-%s:%s\r\n".format(error.getClass().getName(), error.getMessage())), encryptor))
      	}
      } else
      	context become crypto_receive(content, encryptor, decryptor, pkey)
    }
    case PeerClosed     => context stop self
  }
}
