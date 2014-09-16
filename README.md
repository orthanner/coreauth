coreauth
========

COREAUTH is an <a href="http://akka.io">Akka</a>-based network authorization server written in Scala. It utilizes Akka IO subsystem to handle network connections and uses external SQL-compliant RDBMS as a backend for storing information. TLS is supported (certificate format is openssl-compliant), yet not obligatory. However, using unencrypted connections is strongly discouraged.
The protocol is plaintext and consists of two subsets, the first for communicating between client and authentication server and the second for communicating between authentication server and network server utilizing it's functions.
Currently, the following backend stores are supported:
	* <a href="http://www.postgresql.org/">PostgreSQL (preferred)</a>
	* <a href="http://mariadb.org/">MariaDB</a>
	* <a href="http://www.h2database.com/html/main.html">H2</a>
Adding support for other RDBMS is as easy as adding respective driver dependencies to `build.gradle`.
Request/reply formats, as well as table structure, can be checked in `src/main/scala/Server.scala` file (will be extracted and documented later).
