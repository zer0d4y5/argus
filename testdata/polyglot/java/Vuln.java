// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import java.sql.*;
import java.io.*;

public class Vuln {

    // PLANT: SQL injection via string concatenation in Statement.executeQuery (CWE-89)
    public void sqlInjection(String userInput) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
        while (rs.next()) {
            System.out.println(rs.getString(1));
        }
    }

    // PLANT: OS command injection via Runtime.getRuntime().exec with concatenated string (CWE-78)
    public void osCommandInjection(String userInput) throws Exception {
        Process p = Runtime.getRuntime().exec("echo " + userInput);
        p.waitFor();
    }

    // PLANT: Insecure deserialization of user-controlled bytes (CWE-502)
    public Object insecureDeserialization(byte[] userInputBytes) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(userInputBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}
