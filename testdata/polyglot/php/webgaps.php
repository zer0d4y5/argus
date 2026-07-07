<?php
// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.

// PLANT(php-unserialize-req, min-profile=standard, CWE-502): unserialize on request data (argus/curated)
$obj = unserialize($_GET['data']);

// PLANT(php-weak-crypto, min-profile=standard, CWE-327): ECB-mode cipher (argus/curated)
$c = openssl_encrypt($plaintext, "aes-128-ecb", $key);

// PLANT(php-ldap-inj, min-profile=standard, CWE-90): LDAP filter built from request input (argus/curated)
$r = ldap_search($conn, $base, "(uid=" . $_GET['user'] . ")");
