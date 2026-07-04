// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace AppSecFixture
{
    public class Vuln
    {
        // PLANT: SQL injection via string concatenation (CWE-89)
        public void SqlInjection(string userInput)
        {
            string query = "SELECT * FROM Users WHERE Name = '" + userInput + "'";
            using (var conn = new SqlConnection("Server=.;Database=Test;Trusted_Connection=True;"))
            {
                conn.Open();
                var cmd = new SqlCommand(query, conn);
                cmd.ExecuteNonQuery();
            }
        }

        // PLANT: OS command injection via ProcessStartInfo arguments concatenation (CWE-78)
        public void OsCommandInjection(string userInput)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c dir " + userInput,
                UseShellExecute = false
            };
            Process.Start(psi);
        }

        // PLANT: Weak crypto using MD5 for hashing (CWE-328)
        public void WeakCrypto(string userInput)
        {
            var md5 = MD5.Create();
            byte[] inputBytes = Encoding.UTF8.GetBytes(userInput);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            // Do nothing with the hash, just demonstrate usage of weak algorithm
        }
    }
}
