// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import java.io.BufferedReader
import java.io.InputStreamReader
import java.sql.DriverManager
import java.security.MessageDigest

fun osCommandInjection(userInput: String) {
    // PLANT(kt-cmdi, min-profile=max, CWE-78): OS command injection via Runtime.exec with concatenated user input
    val process = Runtime.getRuntime().exec("echo " + userInput)
    val reader = BufferedReader(InputStreamReader(process.inputStream))
    println(reader.readLine())
}

fun sqlInjection(userInput: String) {
    // PLANT-GAP: SQL injection via Statement.executeQuery with concatenated user input (CWE-89) — caught by no profile
    val url = "jdbc:h2:mem:test"
    val conn = DriverManager.getConnection(url, "sa", "")
    val stmt = conn.createStatement()
    val rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'")
    while (rs.next()) {
        println(rs.getString(1))
    }
}

fun weakCrypto(userInput: String): String {
    // PLANT(kt-weak-hash, min-profile=standard, CWE-328): weak crypto using MD5 for password hashing
    val md = MessageDigest.getInstance("MD5")
    val hashBytes = md.digest(userInput.toByteArray())
    return hashBytes.joinToString("") { "%02x".format(it) }
}

fun main() {
    val input = "test' OR '1'='1"
    osCommandInjection(input)
    sqlInjection(input)
    println(weakCrypto(input))
}
