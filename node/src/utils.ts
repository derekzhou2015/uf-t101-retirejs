type LogMethod = (...message: unknown[]) => void;

export function info(options: { logger?: LogMethod }) {
  return function (...message: unknown[]) {
    (options.logger || console.log)(message);
  };
}

export function warn(options: { warnlogger?: LogMethod; logger?: LogMethod }) {
  return function (...message: unknown[]) {
    (options.warnlogger || options.logger || console.warn)(message);
  };
}

export function pick(p: Record<string, unknown>, keys: string[]): Record<(typeof keys)[number], unknown> {
  const result: Record<(typeof keys)[number], unknown> = {};
  keys.forEach((k) => {
    if (k in p) {
      result[k] = p[k];
    }
  });
  return result;
}

export function flatten<T>(e: T[][]): T[] {
  return e.reduce((x, y) => x.concat(y), [] as T[]);
}

/**
 * Normalizes path separators to '/' so ignore patterns and candidate paths
 * are compared in a platform-independent form (Windows '\' vs POSIX '/').
 */
export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

/**
 * Compiles an ignore-path glob into a RegExp. Separators are normalized to
 * '/' first, so the same pattern behaves identically on every platform:
 * '*' matches within a single path segment, '**' matches across segments.
 * Candidate paths must be passed through normalizePath before being tested
 * against the returned RegExp.
 */
export function compileIgnorePath(pattern: string): RegExp {
  const escaped = normalizePath(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const globbed = escaped.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
  return new RegExp(globbed);
}
