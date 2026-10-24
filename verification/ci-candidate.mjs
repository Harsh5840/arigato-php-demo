import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { allowedPaths, inspect, readContents, root, verifierDigest } from './policy.mjs';

const [directory, baseSha, headSha] = process.argv.slice(2);
assert.ok(directory && /^[a-f0-9]{40}$/.test(baseSha) && /^[a-f0-9]{40}$/.test(headSha), 'Expected candidate path and exact base/head SHA values.');
const candidate = resolve(directory);
const git = (...args) => execFileSync('git', args, { cwd: candidate, encoding: 'utf8', timeout: 10000 }).trim();
assert.equal(git('rev-parse', 'HEAD'), headSha, 'Candidate identity must match.');
assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(), baseSha, 'Oracle must match recorded baseline.');
const paths = git('diff', '--name-only', baseSha, headSha, '--').split('\n').filter(Boolean).sort();
assert.deepEqual(paths, [...allowedPaths].sort(), 'Only the approved three files may change.');
assert.equal(verifierDigest(candidate), verifierDigest(root), 'Verifier identity changed.');
const baseline = readContents(root);
const source = readContents(candidate);
// Docker parser directives are executable build configuration, not inert comments.
// In particular, syntax= can fetch an external frontend before RUN network limits apply.
assert.equal(/^\s*#\s*(syntax|escape|check)\s*=/im.test(source.Dockerfile), false, 'Docker parser directives are outside the approved fixture scope.');
const assessment = inspect(source);
assert.equal(inspect(baseline).affected_version_match, true, 'Oracle must be the affected baseline.');
assert.equal(assessment.security_policy, 'PASS', 'Candidate policy must pass.');

// Keep all executable instructions and app code unchanged in this fixture.
const instructions = text => text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#') && !line.startsWith('FROM '));
assert.deepEqual(instructions(source.Dockerfile), instructions(baseline.Dockerfile), 'Unexpected Docker instruction change.');
const baselineComposer = JSON.parse(baseline['composer.json']);
const candidateComposer = JSON.parse(source['composer.json']);
baselineComposer.require.php = candidateComposer.require.php;
assert.deepEqual(candidateComposer, baselineComposer, 'Only Composer PHP floor may change.');
const directives = text => text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith(';'));
assert.deepEqual(directives(source['config/security.ini']), directives(baseline['config/security.ini']).map(line => line.replace(/^session\.upload_progress\.enabled\s*=\s*1$/, 'session.upload_progress.enabled = 0')), 'Unexpected startup setting change.');
console.log(JSON.stringify({
  evidence_class: 'frozen_oracle_candidate_policy',
  execution_origin: 'candidate_source_not_attested_by_verifier',
  base_sha: baseSha, candidate_sha: headSha, changed_paths: paths,
  verifier_sha256: verifierDigest(root),
  source_snapshot: JSON.parse(readFileSync(resolve(root, 'demo/advisory.json'), 'utf8')),
  assessment, runtime_checks: 'SEPARATE_CI_STEPS',
  merge_ready: false, finding_closed: false,
}, null, 2));
