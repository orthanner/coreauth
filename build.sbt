import AssemblyKeys._

name := """coreauth"""

version := "1.0"

scalaVersion := "2.11.1"

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.3.3",
  "com.typesafe.akka" %% "akka-testkit" % "2.3.3" % "test",
  "org.postgresql" % "postgresql" % "9.3-1101-jdbc41",
  "org.apache.commons" % "commons-dbcp2" % "2.0.1",
  "commons-codec" % "commons-codec" % "1.9",
//  "javax.servlet" % "javax.servlet-api" % "3.1.0" % "provided",
  "org.scalatest" %% "scalatest" % "2.1.6" % "test",
  "junit" % "junit" % "4.11" % "test",
  "com.novocode" % "junit-interface" % "0.10" % "test",
//  "org.eclipse.jetty" % "jetty-webapp" % "9.1.0.v20131115" % "container",
//  "org.eclipse.jetty" % "jetty-plus"   % "9.1.0.v20131115" % "container",
  "commons-daemon" % "commons-daemon" % "1.0.15"
)

testOptions += Tests.Argument(TestFrameworks.JUnit, "-v")

//seq(webSettings :_*)

assemblySettings

jarName in assembly := "coreauth.jar"

mainClass in assembly := Some("ServiceApplication")
