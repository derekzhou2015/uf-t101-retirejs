import { beforeEach, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { compileIgnorePath, normalizePath } from '../../lib/utils';
import * as scanner from '../../lib/scanner';
import { Finding, Options, Repository } from '../../lib/types';
import { options } from '../options';

// Cross-platform ignore-path behavior: a pattern must produce the same
// verdict on Windows and POSIX. Patterns and candidates are normalized to
// '/' separators, '*' stays within one path segment, '**' spans segments.

const repo: Repository = {
  sample: {
    extractors: { filename: ['sample-([0-9.]+)[.]js'] },
    vulnerabilities: [{ below: '2', severity: 'high', cwe: [], identifiers: {}, info: [] }],
  },
};

const findings: Finding[] = [];
scanner.on('vulnerable-dependency-found', (finding) => findings.push(finding));
beforeEach(() => {
  findings.length = 0;
});

function ignoreOptions(...patterns: string[]): Options {
  return {
    ...options,
    ignore: { ...options.ignore, pathsAsString: patterns, paths: patterns.map(compileIgnorePath) },
  };
}

describe('compileIgnorePath', () => {
  it('compiles forward-slash and backslash spellings to the same regex', () => {
    assert.equal(
      compileIgnorePath('node_modules/jquery/*').source,
      compileIgnorePath('node_modules\\jquery\\*').source,
    );
  });

  it('single star matches within one path segment only', () => {
    // Patterns are unanchored (relative patterns match as substrings), so the
    // segment boundary is observable when the pattern continues after '*'.
    const re = compileIgnorePath('libs/*.js');
    assert.ok(re.test('libs/sample-1.0.js'));
    assert.ok(!re.test('libs/deep/sample-1.0.js'));
    assert.ok(!re.test('libs/deep/nested/sample-1.0.js'));
  });

  it('double star matches across path segments', () => {
    const re = compileIgnorePath('libs/**');
    assert.ok(re.test('libs/sample-1.0.js'));
    assert.ok(re.test('libs/deep/nested/sample-1.0.js'));
  });
});

describe('normalizePath', () => {
  it('converts windows separators to forward slashes', () => {
    assert.equal(normalizePath('a\\b\\c.js'), 'a/b/c.js');
    assert.equal(normalizePath('a/b/c.js'), 'a/b/c.js');
  });
});

describe('scanner path ignores', () => {
  it('emits a finding when nothing is ignored (control)', async () => {
    await scanner.scanJsFile(path.join('libs', 'sample-1.0.js'), repo, options);
    assert.equal(findings.length, 1);
  });

  it('applies json-ignorefile relative patterns with hierarchy on native paths', async () => {
    // .retireignore.json path entries are kept verbatim (forward slashes);
    // walked paths use the platform separator ('\' on Windows).
    const file = path.join('node_modules', 'jquery', 'sample-1.0.js');
    await scanner.scanJsFile(file, repo, ignoreOptions('node_modules/jquery'));
    assert.equal(findings.length, 0);
  });

  it('single-star cli pattern ignores one segment but not deeper paths', async () => {
    // Pre-fix on Windows '[^/]*' also matched '\', so 'generated/*.js'
    // swallowed files in deeper directories; on Linux it never did.
    const opts = ignoreOptions(path.resolve('generated/*.js'));
    await scanner.scanJsFile(path.join('generated', 'sample-1.0.js'), repo, opts);
    assert.equal(findings.length, 0);
    await scanner.scanJsFile(path.join('generated', 'deep', 'sample-1.0.js'), repo, opts);
    assert.equal(findings.length, 1);
  });

  it('double-star pattern ignores arbitrarily deep paths', async () => {
    const opts = ignoreOptions(path.resolve('libs/**'));
    await scanner.scanJsFile(path.join('libs', 'deep', 'nested', 'sample-1.0.js'), repo, opts);
    assert.equal(findings.length, 0);
  });
});
