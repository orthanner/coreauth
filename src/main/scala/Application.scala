import akka.actor.{Props, ActorSystem}
import akka.io.IO

class Application() extends ApplicationLifecycle {

  private[this] var started: Boolean = false

  private val applicationName = "coreauth"

  implicit val actorSystem = ActorSystem(s"$applicationName-system")

  def start() {
    //logger.info(s"Starting $applicationName Service")

    if (!started) {
      started = true

      val myService = actorSystem.actorOf(Props[Server], "auth-service")

    }
  }

  def stop() {
    //logger.info(s"Stopping $applicationName Service")

    if (started) {
      started = false
      actorSystem.shutdown()
    }
  }

}
