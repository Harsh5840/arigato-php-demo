import test from 'node:test';
import assert from 'node:assert/strict';
import { allowedPaths, fixedVersion, inspect, inspectProposedPatch, readContents, reviewedDigest, root, verifierDigest, versionCompare } from './policy.mjs';

test('baseline assessment identifies affected inventory while security policy FAILS', () => {
  const result = inspect(readContents(root));
  assert.equal(result.runtime_version, '8.3.35');
  assert.equal(result.affected_version_match, true);
  assert.equal(result.security_policy, 'FAIL');
  assert.equal(result.checks.find((check) => check.id === 'upload_progress_startup_setting').pass, false);
});

test('proposed three-file repair actually applies in a scratch directory and passes static candidate policy', () => {
  const before = readContents(root);
  const digest = verifierDigest();
  const result = inspectProposedPatch();
  assert.equal(result.runtime_version, fixedVersion);
  assert.equal(result.affected_version_match, false);
  assert.equal(result.security_policy, 'PASS');
  assert.deepEqual(readContents(root), before, 'checking the patch must not modify the baseline');
  assert.equal(verifierDigest(), digest, 'verifier identity must remain unchanged');
  assert.deepEqual(allowedPaths, ['Dockerfile', 'composer.json', 'config/security.ini']);
});

test('a version-only bump does not conceal missing digest, Composer floor or configuration follow-up', () => {
  const candidate = { ...readContents(root) };
  candidate.Dockerfile = candidate.Dockerfile.replace('8.3.35', fixedVersion);
  const result = inspect(candidate);
  assert.equal(result.affected_version_match, false);
  assert.equal(result.security_policy, 'FAIL');
  for (const id of ['reviewed_image_digest', 'composer_floor', 'upload_progress_startup_setting']) {
    assert.equal(result.checks.find((check) => check.id === id).pass, false);
  }
});

test('duplicate startup directives fail closed rather than accepting an earlier disabled value', () => {
  const candidate = { ...readContents(root) };
  candidate['config/security.ini'] = 'session.upload_progress.enabled = 0\nsession.upload_progress.enabled = 1\n';
  assert.equal(inspect(candidate).checks.find((check) => check.id === 'upload_progress_startup_setting').pass, false);
});

test('unrecognized runtime families are unknown and cannot pass the scoped PHP8.3 policy', () => {
  const candidate = { ...readContents(root) };
  candidate.Dockerfile = candidate.Dockerfile.replace('php:8.3.35-cli-bookworm', `php:8.4.27-cli-bookworm@sha256:${reviewedDigest}`);
  const result = inspect(candidate);
  assert.equal(result.affected_version_match, 'unknown');
  assert.equal(result.security_policy, 'FAIL');
});

test('numeric version comparison does not confuse PHP8.3.9 with PHP8.3.36', () => {
  assert.equal(versionCompare('8.3.9', '8.3.36'), -1);
  assert.equal(versionCompare('8.3.36', '8.3.36'), 0);
  assert.equal(versionCompare('8.3.100', '8.3.36'), 1);
  assert.throws(() => versionCompare('8.3-latest', '8.3.36'));
});

test('Composer cannot require a version newer than the selected interpreter', () => {
  const candidate = { ...readContents(root) };
  candidate.Dockerfile = candidate.Dockerfile.replace('php:8.3.35-cli-bookworm', `php:${fixedVersion}-cli-bookworm@sha256:${reviewedDigest}`);
  candidate['composer.json'] = candidate['composer.json'].replace('>=8.3.35 <8.4', '>=8.3.37 <8.4');
  const result = inspect(candidate);
  assert.equal(result.checks.find((check) => check.id === 'composer_floor').pass, false);
  assert.equal(result.security_policy, 'FAIL');
});
