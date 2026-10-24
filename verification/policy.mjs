import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const allowedPaths = ['Dockerfile', 'composer.json', 'config/security.ini'];
export const fixedVersion = '8.3.36';
export const reviewedDigest = 'cdb77e306d6bb99db40e513fbe036ecc6c53b575cbcb7e581387845fef26d755';
const frozenPaths = ['verification/policy.mjs', 'verification/policy.test.mjs', 'verification/business.php', 'verification/runtime-probe.php', 'verification/ci-candidate.mjs'];

export function versionCompare(left, right) {
  const parse = (version) => {
    if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`Unsupported version: ${version}`);
    return version.split('.').map(Number);
  };
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index++) {
    if (a[index] !== b[index]) return Math.sign(a[index] - b[index]);
  }
  return 0;
}

export function inspect(contents) {
  const fromLines = contents.Dockerfile.split(/\r?\n/).filter((line) => /^FROM\s/i.test(line));
  const image = fromLines.length === 1 ? fromLines[0].match(/^FROM php:(8\.3\.\d+)-cli-bookworm(?:@sha256:([a-f0-9]{64}))?\s*$/) : null;
  const composer = JSON.parse(contents['composer.json']);
  const constraint = typeof composer.require?.php === 'string' ? composer.require.php : '';
  const floor = constraint.match(/^>=(8\.3\.\d+) <8\.4$/)?.[1] ?? null;
  const settings = contents['config/security.ini'].split(/\r?\n/).filter((line) => /^\s*session\.upload_progress\.enabled\s*=/.test(line));
  const uploadProgress = settings.length === 1 ? settings[0].match(/^\s*session\.upload_progress\.enabled\s*=\s*([01])\s*(?:;.*)?$/)?.[1] ?? null : null;
  const runtimeVersion = image?.[1] ?? null;
  const checks = [
    { id: 'docker_parser_directives_absent', pass: !/^\s*#\s*(syntax|escape|check)\s*=/im.test(contents.Dockerfile), detail: 'No model-controlled build frontend, escape or check parser directives are permitted.' },
    { id: 'reviewed_runtime_release', pass: runtimeVersion === fixedVersion, detail: runtimeVersion ?? 'unrecognized runtime declaration' },
    { id: 'reviewed_image_digest', pass: image?.[2] === reviewedDigest, detail: image?.[2] ?? 'no reviewed digest pin' },
    { id: 'composer_floor', pass: floor !== null && runtimeVersion !== null && versionCompare(floor, fixedVersion) >= 0 && versionCompare(floor, runtimeVersion) <= 0, detail: constraint || 'missing PHP constraint' },
    { id: 'upload_progress_startup_setting', pass: uploadProgress === '0', detail: uploadProgress ?? 'missing, duplicated or unrecognized setting' },
    { id: 'startup_config_is_copied', pass: /^COPY config\/security\.ini \/usr\/local\/etc\/php\/conf\.d\/zz-sakurashop\.ini\s*$/m.test(contents.Dockerfile), detail: 'expected startup configuration COPY' },
    { id: 'unprivileged_fixture_user', pass: /^USER 10001:10001\s*$/m.test(contents.Dockerfile), detail: 'expected fixture user' },
  ];
  return {
    evidence_class: 'static_runtime_inventory_policy',
    advisory_ids: ['CVE-2026-109618', 'CVE-2026-109619'],
    inventory_kind: 'synthetic_repository_fixture',
    runtime_version: runtimeVersion,
    affected_version_match: runtimeVersion === null ? 'unknown' : versionCompare(runtimeVersion, fixedVersion) < 0,
    security_policy: checks.every((check) => check.pass) ? 'PASS' : 'FAIL',
    checks,
    limitation: 'Static declaration assessment only; no installed runtime, RCE reproduction, deployment or containment is established.',
  };
}

export function readContents(directory) {
  return Object.fromEntries(allowedPaths.map((path) => [path, readFileSync(join(directory, path), 'utf8')]));
}

export function verifierDigest(directory = root) {
  const entries = frozenPaths.map((path) => [path, createHash('sha256').update(readFileSync(join(directory, path))).digest('hex')]);
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

export function inspectProposedPatch(directory = root) {
  const patchPath = join(directory, 'demo', 'proposed-repair.patch');
  const patch = readFileSync(patchPath, 'utf8');
  const headers = [...patch.matchAll(/^diff --git a\/(.+) b\/(.+)$/gm)];
  const paths = headers.map((match) => match[1]).sort();
  if (headers.some((match) => match[1] !== match[2]) || JSON.stringify(paths) !== JSON.stringify([...allowedPaths].sort())) {
    throw new Error('Repair patch must change exactly the three allowed fixture files.');
  }

  const scratch = mkdtempSync(join(tmpdir(), 'sakurashop-review-'));
  try {
    mkdirSync(join(scratch, 'config'));
    for (const path of allowedPaths) copyFileSync(join(directory, path), join(scratch, path));
    for (const args of [['apply', '--no-index', '--check', patchPath], ['apply', '--no-index', patchPath]]) {
      const result = spawnSync('git', args, { cwd: scratch, encoding: 'utf8', timeout: 10000, shell: false });
      if (result.error || result.status !== 0) throw new Error(result.error?.message ?? result.stderr.trim() ?? 'Patch could not be applied.');
    }
    return inspect(readContents(scratch));
  } finally {
    if (dirname(resolve(scratch)) !== resolve(tmpdir()) || !basename(scratch).startsWith('sakurashop-review-')) {
      throw new Error('Refusing cleanup outside the verified temporary fixture directory.');
    }
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const mode = process.argv[2] ?? '--require-fixed';
    if (!['--expect-affected', '--require-fixed', '--proposed'].includes(mode)) throw new Error('Unknown mode.');
    const assessment = mode === '--proposed' ? inspectProposedPatch() : inspect(readContents(root));
    const expectedAssessment = mode === '--expect-affected';
    const passed = expectedAssessment ? assessment.affected_version_match === true && assessment.security_policy === 'FAIL' : assessment.security_policy === 'PASS';
    console.log(JSON.stringify({
      assessment_purpose: expectedAssessment ? 'Confirm intentionally affected demo baseline; this is not a security pass.' : mode === '--proposed' ? 'Check unapplied proposed diff in a temporary directory; repository baseline remains unchanged.' : 'Require reviewed candidate policy on current repository files.',
      assessment_result: passed ? 'PASS' : 'FAIL',
      ...assessment,
      verifier_sha256: verifierDigest(),
      runtime_execution: 'NOT_RUN_BY_THIS_COMMAND',
      human_review: 'REQUIRED',
    }, null, 2));
    process.exitCode = passed ? 0 : 1;
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
