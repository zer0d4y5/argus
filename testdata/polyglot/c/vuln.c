/* Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
 * Never compiled; exists only to be scanned by semgrep. C is covered at
 * standard by p/security-audit's C rules (no dedicated p/c added — it caught
 * nothing p/security-audit missed on these plants; see docs/coverage.md).
 *
 * PLANT(id, min-profile, CWE) = recall-eval plant; PLANT-GAP = a real
 * weakness no curated profile catches (honest gap). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *take_input(int argc, char **argv) {
    return argc > 1 ? argv[1] : "";
}

/* PLANT-GAP: strcpy into a fixed stack buffer (buffer overflow, CWE-120). It
 * IS flagged (insecure-use-string-copy-fn) but semgrep classes it CWE-676
 * "use of dangerous function" — the same CWE the gets() plant below owns, so
 * only one CWE-676 plant can be labeled per file; this one is documented as a
 * gap for its intended overflow classification. */
void copy_input(const char *user_input) {
    char buf[64];
    strcpy(buf, user_input);
    printf("%s\n", buf);
}

/* PLANT-GAP: user input as the printf format string (CWE-134) — uncaught. */
void log_input(const char *user_input) {
    printf(user_input);
}

/* PLANT-GAP: system() with concatenated input (CWE-78) — uncaught. */
void run_cmd(const char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input);
    system(cmd);
}

/* PLANT(c-gets, min-profile=standard, CWE-676): p/security-audit's
 * insecure-use-gets-fn flags the inherently dangerous gets(). */
void read_line(void) {
    char line[128];
    gets(line);
}

int main(int argc, char **argv) {
    char *input = take_input(argc, argv);
    copy_input(input);
    log_input(input);
    run_cmd(input);
    read_line();
    return 0;
}
