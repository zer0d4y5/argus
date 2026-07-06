// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Never compiled; exists only to be scanned by semgrep (p/scala, in standard).
//
// PLANT(id, min-profile, CWE) = recall-eval plant; PLANT-GAP = a real
// weakness no curated profile catches (honest gap, docs/coverage.md).

import java.security.MessageDigest
import java.sql.{Connection, DriverManager}
import scala.sys.process._

object Vuln {

  def takeInput(args: Array[String]): String =
    if (args.nonEmpty) args(0) else ""

  // PLANT(scala-sqli, min-profile=standard, CWE-89): p/scala's tainted-sql-string
  // rule flags SQL built by string interpolation of untrusted input.
  def sqli(userInput: String, conn: Connection): Unit = {
    val stmt = conn.createStatement()
    stmt.executeQuery(s"SELECT * FROM users WHERE name = '$userInput'")
  }

  // PLANT-GAP: shell invocation with concatenated input (CWE-78) — uncaught.
  def cmdi(userInput: String): Unit = {
    Seq("/bin/sh", "-c", "echo " + userInput).!
  }

  // PLANT-GAP: MD5 over sensitive input (CWE-328) — uncaught.
  def weakHash(userInput: String): Array[Byte] = {
    val md = MessageDigest.getInstance("MD5")
    md.digest(userInput.getBytes("UTF-8"))
  }

  // PLANT-GAP: unsafe Java deserialization (CWE-502) — uncaught.
  def deserialize(bytes: Array[Byte]): AnyRef = {
    val in = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes))
    in.readObject()
  }

  // PLANT-GAP: hardcoded DB password (CWE-798) — semgrep's scala pack has no
  // hardcoded-secret rule; gitleaks (SECRET) is the platform's answer here.
  val dbPassword = "S3cr3tP@ssw0rd!"

  def main(args: Array[String]): Unit = {
    val input = takeInput(args)
    val conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", dbPassword)
    sqli(input, conn)
    cmdi(input)
    weakHash(input)
  }
}
