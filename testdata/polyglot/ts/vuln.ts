// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as crypto from 'crypto';

export function runCommand(userInput: string): void {
  // PLANT(ts-cmdi, min-profile=standard, CWE-78): OS command injection via child_process.execSync with interpolated user input
  execSync(`echo ${userInput}`);
}

export function readSensitiveFile(filename: string): string {
  const baseDir = '/etc';
  // PLANT-GAP: path traversal via concatenated user filename (CWE-22) — caught by no profile; tracked in docs/coverage.md
  const filePath = baseDir + '/' + filename;
  return fs.readFileSync(filePath, 'utf8');
}

export function hashPassword(password: string): string {
  // PLANT(ts-weak-hash, min-profile=max, CWE-327): weak crypto — createHash("md5") on a password (textbook CWE-328; semgrep emits CWE-327)
  return crypto.createHash('md5').update(password).digest('hex');
}
