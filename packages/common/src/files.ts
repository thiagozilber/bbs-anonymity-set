import {chmodSync, closeSync, openSync, readFileSync, writeFileSync, writeSync} from 'node:fs';

export function readJson<T>(path: string): T {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`opening ${path}: ${(e as Error).message}`);
  }
  try {
    return JSON.parse(text) as T;
  } catch (e) {
    throw new Error(`parsing ${path}: ${(e as Error).message}`);
  }
}

export function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

/**
 * Like `writeJson`, but only the owner can read or write the file (mode
 * 0600). Use it for anything holding secret key material.
 *
 * The mode given to `open` only applies when the file is created, so an
 * existing file (e.g. `keygen --force`) is also chmod-ed. That happens after
 * truncation and before any write, so the old permissions never cover new key
 * material.
 */
export function writeJsonPrivate(path: string, value: unknown): void {
  const fd = openSync(path, 'w', 0o600);
  try {
    chmodSync(path, 0o600);
    writeSync(fd, JSON.stringify(value, null, 2) + '\n');
  } finally {
    closeSync(fd);
  }
}

/** Reads a JSON Lines file. Blank lines are skipped. */
export function readJsonl<T>(path: string): T[] {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`opening ${path}: ${(e as Error).message}`);
  }
  const out: T[] = [];
  text.split('\n').forEach((line, i) => {
    if (line.trim() === '') {
      return;
    }
    try {
      out.push(JSON.parse(line) as T);
    } catch (e) {
      throw new Error(`${path}: line ${i + 1}: ${(e as Error).message}`);
    }
  });
  return out;
}

/** Writes a JSON Lines file, one value per line. */
export function writeJsonl(path: string, items: Iterable<unknown>): void {
  let text = '';
  for (const item of items) {
    text += JSON.stringify(item) + '\n';
  }
  writeFileSync(path, text);
}
