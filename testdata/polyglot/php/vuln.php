<?php
// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.

// PLANT(php-sqli, min-profile=standard, CWE-89): SQL injection via string concatenation in mysqli_query
$conn = new mysqli("localhost", "root", "", "testdb");
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $sql);

// PLANT(php-cmdi, min-profile=standard, CWE-78): OS command injection via system() with unescaped user input
$host = $_GET['host'];
system("ping -c 4 " . $host);

// PLANT(php-xss, min-profile=standard, CWE-79): reflected XSS by echoing raw GET parameter into HTML context
$name = $_GET['name'];
echo "<h1>Welcome, " . $name . "</h1>";

// PLANT(php-lfi, min-profile=max, CWE-98): local file inclusion via unvalidated user input in include() (textbook CWE-22; semgrep emits CWE-98)
$file = $_GET['file'];
include($file);
?>
