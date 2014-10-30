name := "Coreauth"

version := "1.0"

scalaVersion := "2.11.2"

resolvers += "Spring IO" at "http://repo.spring.io/release"

val springVersion = "4.1.1.RELEASE"
val akkaVersion = "2.3.6"

lazy val hello = taskKey[Unit]("An example task")

hello := { println("Hello!") }

libraryDependencies ++= Seq(
	"com.typesafe.akka" %% "akka-actor" % akkaVersion,
	"com.typesafe.akka" %% "akka-cluster" % akkaVersion,
    "org.scala-lang.modules" %% "scala-async" % "0.9.2",
	"com.typesafe" % "config" % "1.2.1",
	"org.postgresql" % "postgresql" % "9.3-1101-jdbc41",
	"org.mariadb.jdbc" % "mariadb-java-client" % "1.1.7",
	"com.h2database" % "h2" % "1.4.181",
    "org.apache.commons" % "commons-dbcp2" % "2.0.1",
	"commons-codec" % "commons-codec" % "1.9",
	"org.springframework" % "spring-context" % springVersion,
	"org.springframework" % "spring-jdbc" % springVersion,
	"org.springframework" % "spring-tx" % springVersion
)
