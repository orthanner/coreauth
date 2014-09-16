coreauth
========

COREAUTH is an <a href="http://akka.io">Akka</a>-based network authorization server written in Scala. It utilizes Akka IO subsystem to handle network connections and uses external SQL-compliant RDBMS as a backend for storing information. TLS is supported (certificate format is openssl-compliant), yet not obligatory. However, using unencrypted connections is strongly discouraged.
The protocol is plaintext and consists of two subsets, the first for communicating between client and authentication server and the second for communicating between authentication server and network server utilizing it's functions.
Currently, the following backend stores are supported:

* [PostgreSQL](http://www.postgresql.org/) (preferred)
* [MariaDB](http://mariadb.org/)
* [H2](http://www.h2database.com/html/main.html)

Adding support for other RDBMS is as easy as adding appropriate driver dependencies to `build.gradle` and creating an SQL schema file.
Request/reply format can be checked in `src/main/scala/Server.scala` file (will be extracted and documented later).
For table schema for your database, please check the appropriate sql script.
