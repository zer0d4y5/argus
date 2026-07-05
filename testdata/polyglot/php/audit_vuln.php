<?php
// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.

// PLANT-GAP: variable extraction from user input via extract() (CWE-621) — caught by no profile
extract($_GET);

// PLANT(php-dynamic-include, min-profile=max, CWE-98): dynamic include from user input
include($_GET['page']);

// PLANT-GAP: predictable PRNG for a token via rand() (CWE-330) — caught by no profile
$token = rand();
echo $token;
