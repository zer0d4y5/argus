/* Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix. */
/* Web-gap classes caught by argus/curated rules the registry packs miss. */
#include <stdio.h>
#include <stdlib.h>

void fmt(char *user) {
    /* PLANT(c-format-string, min-profile=standard, CWE-134): non-literal printf format (argus/curated) */
    printf(user);
}

void cmdi(char *cmd) {
    /* PLANT(c-cmdi, min-profile=standard, CWE-78): system() on a non-constant command (argus/curated) */
    system(cmd);
}
