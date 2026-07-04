<?php
// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.

// PLANT: SQL injection via string concatenation in mysqli_query (CWE-89)
$conn = new mysqli("localhost", "root", "", "testdb");
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $sql);

// PLANT: OS command injection via system() with unescaped user input (CWE-78)
$host = $_GET['host'];
system("ping -c 4 " . $host);

// PLANT: Reflected XSS by echoing raw GET parameter into HTML context (CWE-79)
$name = $_GET['name'];
echo "<h1>Welcome, " . $name . "</h1>";

// PLANT: Local File Inclusion via unvalidated user input in include() (CWE-22)
$file = $_GET['file'];
include($file);
?>
