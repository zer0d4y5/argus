/* Safe-code plants for the FP measurement eval. */
#include <stdio.h>
#include <stdlib.h>

/* PLANT-FP(c-safe-format, CWE-134): constant format string. */
void fmt(char *user) { printf("%s", user); }

/* PLANT-FP(c-safe-cmdi, CWE-78): constant command. */
void cmdi(void) { system("uptime"); }
