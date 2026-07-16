import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import stylelint from 'stylelint';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const siteRoot = path.resolve(scriptDirectory, '..');
export const baselinePath = path.join(siteRoot, 'stylelint-baseline.json');

function findingKey(finding) {
  return JSON.stringify(finding);
}

function compareFinding(left, right) {
  return findingKey(left).localeCompare(findingKey(right));
}

export function normalizeFindings(findings) {
  return findings
    .map(({ file, rule, text }) => ({ file, rule, text }))
    .sort(compareFinding);
}

export function compareFindings(actual, expected) {
  const actualCounts = new Map();
  const expectedCounts = new Map();
  for (const finding of normalizeFindings(actual)) {
    const key = findingKey(finding);
    actualCounts.set(key, (actualCounts.get(key) ?? 0) + 1);
  }
  for (const finding of normalizeFindings(expected)) {
    const key = findingKey(finding);
    expectedCounts.set(key, (expectedCounts.get(key) ?? 0) + 1);
  }

  const newFindings = [];
  const missingFindings = [];
  const keys = new Set([...actualCounts.keys(), ...expectedCounts.keys()]);
  for (const key of [...keys].sort()) {
    const actualCount = actualCounts.get(key) ?? 0;
    const expectedCount = expectedCounts.get(key) ?? 0;
    const finding = JSON.parse(key);
    if (actualCount > expectedCount) {
      for (let index = 0; index < actualCount - expectedCount; index += 1) newFindings.push(finding);
    }
    if (expectedCount > actualCount) {
      for (let index = 0; index < expectedCount - actualCount; index += 1) missingFindings.push(finding);
    }
  }
  return { newFindings, missingFindings };
}

function relativeSource(source) {
  return path.relative(siteRoot, source).split(path.sep).join('/');
}

export async function collectFindings() {
  const result = await stylelint.lint({
    configFile: path.join(siteRoot, 'stylelint.config.mjs'),
    cwd: siteRoot,
    files: 'app/**/*.css',
  });
  const findings = [];
  for (const file of result.results) {
    const source = file.source ? relativeSource(file.source) : '<unknown>';
    for (const warning of file.warnings) {
      findings.push({ file: source, rule: warning.rule, text: warning.text });
    }
    for (const warning of file.invalidOptionWarnings) {
      findings.push({
        file: source,
        rule: 'invalid-option',
        text: warning.text ?? warning.message ?? String(warning),
      });
    }
    for (const error of file.parseErrors) {
      findings.push({ file: source, rule: 'parse-error', text: error.reason });
    }
  }
  return normalizeFindings(findings);
}

async function readBaseline() {
  return normalizeFindings(JSON.parse(await readFile(baselinePath, 'utf8')));
}

async function writeBaseline(findings) {
  await writeFile(baselinePath, `${JSON.stringify(normalizeFindings(findings), null, 2)}\n`);
}

function printFindings(label, findings) {
  if (findings.length === 0) return;
  console.error(`${label} (${findings.length}):`);
  for (const finding of findings) console.error(`- ${finding.file} ${finding.rule}: ${finding.text}`);
}

export async function checkBaseline({ update = false } = {}) {
  const actual = await collectFindings();
  if (update) {
    await writeBaseline(actual);
    return { actual, newFindings: [], missingFindings: [] };
  }
  const expected = await readBaseline();
  const comparison = compareFindings(actual, expected);
  if (comparison.newFindings.length || comparison.missingFindings.length) {
    printFindings('New Stylelint findings', comparison.newFindings);
    printFindings('Missing Stylelint baseline entries', comparison.missingFindings);
  }
  return { actual, ...comparison };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const update = process.argv.slice(2).includes('--update');
  const result = await checkBaseline({ update });
  if (update) {
    console.log(`Wrote ${result.actual.length} Stylelint baseline findings.`);
  } else if (result.newFindings.length || result.missingFindings.length) {
    console.error('Stylelint baseline is out of date. Update it explicitly with `npm run lint:css:update`.');
    process.exitCode = 1;
  } else {
    console.log(`Stylelint baseline matches ${result.actual.length} findings.`);
  }
}
