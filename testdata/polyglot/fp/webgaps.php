<?php
// Safe-code plants for the FP measurement eval.

// PLANT-FP(php-safe-deser, CWE-502): json_decode cannot instantiate objects.
$obj = json_decode($_GET['data'], true);

// PLANT-FP(php-safe-crypto, CWE-327): authenticated AES-GCM.
$c = openssl_encrypt($plaintext, "aes-256-gcm", $key, 0, $iv, $tag);

// PLANT-FP(php-safe-ldap, CWE-90): request value escaped for the filter.
$safe = ldap_escape($_GET['user'], "", LDAP_ESCAPE_FILTER);
$r = ldap_search($conn, $base, "(uid=" . $safe . ")");
