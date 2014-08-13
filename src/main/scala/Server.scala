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
import com.typesafe.config.ConfigFactory
import javax.sql.DataSource
import java.net._
import java.nio._
import java.nio.channels._
import java.nio.charset._

//case class User(id: Int, login: String, password: String)
//case class Realm(id: Int, name: String)
//case class UserAttr(user: Int, name: String, value: String)
//case class Permission(id: Int, name: String)
//case class Profile(id: Int, realm: Int, name: String)
//case class ProfileMapping(user: Int, profile: Int)
//case class PermissionMapping(profile: Int, permission: Int)
//case class Session(id: Int, user: Int, realm: Int, token: String, start: Timestamp, last: Timestamp)

object RequestHander {
  val AUTH = "auth (?<login>[^@]+)@(?<realm>[^\\s]+) (?<password>[\\w]+)".r
  val CHECK = "check (?<token>[A-F0-9]+) (?<address>[.:\\-\\w]+) (?<perm>[:.\\w]+)".r
  val STOP = "logout (?<token>[A-F0-9]+)".r
  val ATTR_QUERY = "get (?<token>[A-F0-9]+)/(?<attr>[\\w.\\-_:]+)".r
  val ATTR_UPDATE = "set (?<token>[A-F0-9]+)/(?<attr>[\\w.\\-_:]+)=(?<value>[\\w]*|\\$)".r //$ -> delete
}

case class Session(uid: Int, realm: String)

class RequestHandler(client: String, DB: DataSource) extends Actor {
  import Tcp._
  import RequestHander._
  import Crypt._
  import Helpers._
  import Base64._

  implicit val exec = context.dispatcher.asInstanceOf[Executor with ExecutionContext]

  def getSession(token: String, address: String)(implicit conn: Connection): Option[Session] = {
    val sq = conn.prepareStatement("select uid, realm from sessions where token=? and address=?")
    sq.setString(1, token)
    sq.setString(2, address)
    val s = sq.executeQuery
    if (s.first()) {
      val update = conn.prepareStatement("update sessions set last=current_timestamp() where token=?")
      update.setString(1, token)
      update.executeUpdate
      Some(Session(s.getInt("uid"), s.getString("realm")))
    } else
      None
  }

  def toOption[T](value: T): Option[T] = if (value == null) None else Some(value)

  def receive = _receive(ByteString.empty)

  def _receive(data: ByteString): Receive = {
    case Received(input) => {
      val content = data ++ input
      val pos = content.indexOfSlice(Seq(13, 10))
      if (pos >= 0) {
	val msg = content.slice(0, pos)
	context become _receive(content.drop(msg.length + 2))
	val message = msg.utf8String.trim()
	val src = sender()
	val c = DB.getConnection
	message match {
	  case AUTH(login, realm, password) => Future {
	    val sid = generateSecureCookie
	    val conn = c
	    try { 
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
		  val insert = conn.prepareStatement("insert into sessions(uid, realm, token, start, last, ip) values(?, ?, current_date(), current_date(), ?)")
		  insert.setInt(1, uid)
		  insert.setString(2, sid)
		  insert.setString(3, client)
		  if (insert.executeUpdate() == 0)
		    throw new SQLException("Could not create session")
		} else
		  throw new java.security.AccessControlException("Specified user cannot access this realm")
	      } else
		throw new java.security.AccessControlException("Invalid credentials")
	    } finally { 
	      conn.close()
	    }
	    sid
	  } onComplete {
	    case Success(sid) => src ! Write(ByteString("+%s\r\n".format(sid)))
	    case Failure(error) => src ! Write(ByteString("-%s:%s\r\n".format(error.getClass().getName(), error.getMessage().split("[\r\n]")(0))))
	  }
	  case CHECK(token, address, permission) => Future {
	    implicit val conn = c
	    getSession(token, address)
	    val query = conn.prepareStatement("select count(*)>0 from user_permissions up left join permissions p on up.perm_id=p.id left join sessions s on s.user_id=up.user_id where s.token=? and s.address=? and p.name=?")
	    query.setString(1, token)
	    query.setString(2, address)
	    query.setString(3, permission)
	    val result = query.executeQuery
	    val r = if (result.first() && result.getBoolean(1)) "+\r\n" else "-\r\n"
	    conn.close()
	    ByteString(r)
	  } onComplete {
	    case Success(c) => src ! Write(c)
	    case Failure(error) => src ! Write(ByteString("-%s:%s\r\n".format(error.getClass().getName(), error.getMessage())))
	  }
	  case STOP(token) => Future {
	    val conn = c
	    val query = conn.prepareStatement("delete from sessions where token=? and address=?")
	    query.setString(1, token)
	    query.setString(2, client)
	    val x = query.executeUpdate
	    conn.close()
	    ByteString((if (x > 0) "+" else "-") + "\r\n")
	  } onComplete {
	    case Success(m) =>
	      src ! Write(m)
	    case Failure(_) =>
	      src ! Write(ByteString("-\r\n"))
	  }
	  case ATTR_QUERY(token, attr) => Future {
	    implicit val conn = c
	    val valueOption = getSession(token, client) match {
	      case Some(session) => {
		val aq = conn.prepareStatement("select value from extra_attrs where name=? and user_id=?")
		aq.setString(1, attr)
		aq.setInt(2, session.uid)
		val result = aq.executeQuery
		if (result.first())
		  toOption(result.getString("value"))
		else
		  None
	      }
	      case None => None
	    }
	    conn.close()
	    valueOption
	  } onComplete {
	    _ match {
	      case Success(value) => src ! Write(ByteString("+%s\r\n".format(value.map{ s => encodeBase64(s.getBytes("UTF-8"))}.getOrElse("$"))))
	      case Failure(_) => src ! Write(ByteString("-\r\n"))
	    }
	  }
	  case ATTR_UPDATE(token, name, value) => Future {
	    implicit val conn = c
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
	    conn.close()
	    result
	  } onComplete {
	    case Success(x) => src ! Write(ByteString("+%s\r\n".format(String.valueOf(x))))
	    case Failure(_) => src ! Write(ByteString("-\r\n"))
	  }
	  case _ => { 
	    src ! Write(ByteString("-Invalid request\r\n"))
	    c.close()
	  }
	}
      }
    }
    case PeerClosed     => context stop self
  }
}

class Server(args: scala.Array[String]) extends Actor {
  import Tcp._
  import context.system

  lazy val config = ConfigFactory.parseFile(new java.io.File(if(args.length > 0) args(0) else "coreauth.conf"))
    .withFallback(ConfigFactory.parseString("udp.interface=" + NetworkInterface.getByIndex(0).getName()))
    .withFallback(ConfigFactory.parseString("udp.port=9876"))
    .withFallback(ConfigFactory.parseString("tcp.port=9876"))

  lazy val DB = {
    val db = new BasicDataSource()
    db setDriverClassName config.getString("jdbc.driver")
    db setUrl config.getString("jdbc.url")

    db setUsername config.getString("jdbc.username")
    db setPassword config.getString("jdbc.password")
    db setMaxTotal config.getInt("jdbc.connLimit")
    db
  }

  
  override def preStart = {
    IO(Tcp) ! Bind(self, new InetSocketAddress(config.getInt("tcp.port")))
  }

  override def postStop = {
    IO(Tcp) ! Unbind
  }
  
  def receive = {
    case b @ Bound(localAddress) => {
      val dc = DatagramChannel.open
        .setOption[java.lang.Boolean](StandardSocketOptions.SO_REUSEADDR, true)
        .bind(new InetSocketAddress(config.getInt("udp.port")))
      val key = dc.join(InetAddress.getByName(config.getString("udp.group")), NetworkInterface.getByName(config.getString("udp.interface")))
      context become listening(dc, key)
    }
  }

  def listening(dc: DatagramChannel, key: MembershipKey): Receive = {
    case c @ Connected(remote, local) =>
      sender() ! Register(context.actorOf(Props(classOf[RequestHandler], remote.getHostString(), DB)))

    case CommandFailed(_: Bind) => context stop self
  }

}

