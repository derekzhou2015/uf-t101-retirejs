import { describe, it } from 'node:test';
import * as fs from 'fs';
import { strict as strictAssert } from 'node:assert';
import * as assert from '../assert';
import * as retire from '../../lib/retire';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);

describe('versions', function () {
  it('should_not_be_vulnerable_release_when_beta_is', function () {
    repo.jquery.vulnerabilities.push({ below: '10.0.0.beta.2' });
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_release_when_all_starting_at_version_is', function () {
    repo.jquery.vulnerabilities.push({ atOrAbove: '10.0.0-*', below: '10.0.1' });
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js', repo);
    assert.isVulnerable(result);
  });

  it('should_not_be_vulnerable_higher_beta_when_beta', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0.beta.2' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.3/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_rc_when_beta', function () {
    repo.jquery.vulnerabilities = [{ below: '1.9.0b1' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.9.0rc1/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_when_at_beta', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0.beta.2' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_when_lower_beta', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0.beta.2' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
  it('should_be_vulnerable_beta_when_below_release', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
  it('should_be_vulnerable_rc_when_below_release', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_when_is_rc_and_lower_beta', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0.beta.2' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_see_min_as_at_or_above_non_min_below', function () {
    repo.jquery.vulnerabilities = [{ below: '3.5.0' }];
    const result = retire.scanUri('https://ajax.googleapis.com/lib/jquery-3.5.0.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_when_version_in_excludes_list', function () {
    repo.jquery.vulnerabilities = [{ atOrAbove: '1.0.0', below: '3.0.0', excludes: ['1.12.4-aem'] }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.12.4-aem/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_when_similar_version_not_in_excludes_list', function () {
    repo.jquery.vulnerabilities = [{ atOrAbove: '1.0.0', below: '3.0.0', excludes: ['1.12.4-aem'] }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js', repo);
    assert.isVulnerable(result);
  });

  // semver §11.4.4: numeric identifiers have lower precedence than alphanumeric ones
  it('should_rank_numeric_prerelease_identifier_below_alphanumeric', function () {
    strictAssert.equal(retire.isAtOrAbove('1.0.0-beta.10', '1.0.0-beta.9a'), false);
    strictAssert.equal(retire.isAtOrAbove('1.0.0-beta.9a', '1.0.0-beta.10'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0-2', '1.0.0-1a'), false);
    strictAssert.equal(retire.isAtOrAbove('1.0.0-1a', '1.0.0-2'), true);
  });
  it('should_compare_numeric_prerelease_identifiers_numerically', function () {
    strictAssert.equal(retire.isAtOrAbove('1.0.0-beta.10', '1.0.0-beta.9'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0-beta.9', '1.0.0-beta.10'), false);
  });
  it('should_rank_release_above_prerelease', function () {
    strictAssert.equal(retire.isAtOrAbove('1.0.0', '1.0.0-beta'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0-beta', '1.0.0'), false);
    strictAssert.equal(retire.isAtOrAbove('1.0.0', '1.0.0-beta.2'), true);
  });
  it('should_treat_missing_numeric_segments_as_zero', function () {
    strictAssert.equal(retire.isAtOrAbove('1.0', '1.0.0'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0', '1.0'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0.1', '1.0.0'), true);
    strictAssert.equal(retire.isAtOrAbove('1.0.0', '1.0.0.1'), false);
  });
  it('should_be_vulnerable_numeric_prerelease_when_below_alphanumeric_bound', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0-beta.9a' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0-beta.10/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_alphanumeric_prerelease_when_above_numeric_bound', function () {
    repo.jquery.vulnerabilities = [{ below: '10.0.0-beta.10' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0-beta.9a/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_in_prerelease_range_spanning_numeric_and_alphanumeric', function () {
    repo.jquery.vulnerabilities = [{ atOrAbove: '10.0.0-beta.2', below: '10.0.0-beta.9a' }];
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/10.0.0-beta.10/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
});
