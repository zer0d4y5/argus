// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as crypto from 'crypto';

export function runCommand(userInput: string): void {
  // PLANT: OS command injection via child_process.execSync with a template string interpolating a userInput: string parameter. (CWE-78)
  execSync(`echo ${userInput}`);
}

export function readSensitiveFile(filename: string): string {
  const baseDir = '/etc';
  // PLANT: Path traversal: fs.readFileSync using path built by concatenating a user-supplied filename onto a base dir, no sanitization. (CWE-22)
  const filePath = baseDir + '/' + filename;
  return fs.readFileSync(filePath, 'utf8');
}

export function hashPassword(password: string): string {
  // PLANT: Weak crypto: use crypto.createHash("md5") to hash a password. (CWE-328)
  return crypto.createHash('md5').update(password).digest('hex');
}
