import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultSiteRoot = path.resolve(scriptDirectory, '..');

// Keep these lists deliberately small. A new global token or compatibility hook
// must be reviewed at the source owner instead of silently entering the cascade.
const retiredTokens = ['bg', 'ink', 'soft', 'muted', 'line', 'primary', 'primary-action'];
const retiredClasses = [
  'coquic-page',
  'ui-button',
  'ui-badge',
  'ui-panel',
  'ui-dialog',
  'ui-scroll-region',
  'ui-skeleton',
  'ui-status-label',
  'ui-table',
  'ui-tabs',
  'article-content',
  'evidence-root',
  'evidence-thread',
  'evidence-message',
  'evidence-disclosure',
  'evidence-code-block',
  'evidence-diff',
  'evidence-markdown',
  'chat-transcript',
  'chat-bubble',
  'tool-card',
  'page-header',
  'page-title',
  'eyebrow',
];
const retiredSheets = [
  'legacy.css',
  'primitives.css',
  'shell.css',
  'editorial.css',
  'evidence.css',
];

async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.next') continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(absolute));
    else files.push(absolute);
  }
  return files;
}

function relative(siteRoot, file) {
  return path.relative(siteRoot, file).split(path.sep).join('/');
}

function sourceFiles(siteRoot, files) {
  return files.filter((file) => {
    const rel = relative(siteRoot, file);
    const isProductionSource = rel.startsWith('app/')
      || rel.startsWith('src/')
      || (rel.startsWith('public/') && path.dirname(rel) === 'public');
    if (!isProductionSource) return false;
    return /\.(?:css|js|jsx|mjs|ts|tsx)$/.test(rel);
  });
}

function importedSheets(content) {
  return [...content.matchAll(/@import\s+(?:url\(\s*)?(?:["']([^"']+)["']|([^'"\s);]+))\s*\)?/gi)]
    .map((match) => match[1] ?? match[2]);
}

function stringVariableInitializers(content) {
  const initializers = new Map();
  for (const match of content.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g)) {
    let start = match.index + match[0].length;
    while (/\s/.test(content[start] ?? '')) start += 1;

    const opening = content[start];
    if (opening !== '"' && opening !== "'" && opening !== '`') continue;
    let end = start + 1;
    while (end < content.length) {
      const character = content[end++];
      if (character === '\\') end += 1;
      else if (character === opening) break;
    }
    initializers.set(match[1], content.slice(start, end));
  }
  return initializers;
}

function classNameInitializers(content) {
  const initializers = [];
  for (const match of content.matchAll(/\bclassName\s*=/g)) {
    let start = match.index + match[0].length;
    while (/\s/.test(content[start] ?? '')) start += 1;

    const opening = content[start];
    let end = start;
    if (opening === '"' || opening === "'") {
      end += 1;
      while (end < content.length) {
        const character = content[end++];
        if (character === '\\') end += 1;
        else if (character === opening) break;
      }
    } else if (opening === '{') {
      let depth = 0;
      let quote;
      while (end < content.length) {
        const character = content[end++];
        if (quote) {
          if (character === '\\') end += 1;
          else if (character === quote) quote = undefined;
        } else if (character === '"' || character === "'" || character === '`') {
          quote = character;
        } else if (character === '{') {
          depth += 1;
        } else if (character === '}') {
          depth -= 1;
          if (depth === 0) break;
        }
      }
    } else {
      continue;
    }
    initializers.push(content.slice(start, end));
  }
  return initializers;
}

function consumesRetiredClass(rel, content, className) {
  const classNamePattern = new RegExp(`(?<![A-Za-z0-9_-])${className}(?![A-Za-z0-9_-])`);
  if (rel.endsWith('.css')) return new RegExp(`\\.${className}(?![A-Za-z0-9_-])`).test(content);

  const selectorPattern = new RegExp(`(?:[\\"'\\\`]|\\s)\\.${className}(?![A-Za-z0-9_-])`);
  if (selectorPattern.test(content)) return true;

  const initializers = classNameInitializers(content);
  if (initializers.some((initializer) => classNamePattern.test(initializer))) return true;

  for (const [identifier, value] of stringVariableInitializers(content)) {
    const identifierPattern = new RegExp(`(?<![A-Za-z0-9_$])${identifier}(?![A-Za-z0-9_$])`);
    if (classNamePattern.test(value) && initializers.some((initializer) => identifierPattern.test(initializer))) return true;
  }
  return false;
}

function add(violations, message) {
  violations.push(message);
}

export async function collectStyleBoundaryViolations(siteRoot = defaultSiteRoot) {
  const violations = [];
  const appRoot = path.join(siteRoot, 'app');
  const stylesRoot = path.join(appRoot, 'styles');
  const allFiles = await walk(siteRoot);

  for (const file of [path.join(appRoot, 'globals.css'), path.join(stylesRoot, 'legacy.css')]) {
    if (await exists(file)) add(violations, `retired file exists: ${relative(siteRoot, file)}`);
  }
  for (const file of allFiles) {
    const rel = relative(siteRoot, file);
    if (rel.startsWith('app/styles/features/')) add(violations, `retired feature stylesheet exists: ${rel}`);
    if (retiredSheets.some((name) => rel === `app/styles/${name}`)) add(violations, `retired shared stylesheet exists: ${rel}`);
  }

  const themePath = path.join(stylesRoot, 'theme.css');
  if (await exists(themePath)) {
    const theme = await readFile(themePath, 'utf8');
    for (const importPath of importedSheets(theme)) {
      if (importPath !== 'tailwindcss') add(violations, `theme imports non-canonical sheet: ${importPath}`);
    }
  } else {
    add(violations, 'canonical theme.css is missing');
  }

  const layoutPath = path.join(appRoot, 'layout.tsx');
  if (await exists(layoutPath)) {
    const layout = await readFile(layoutPath, 'utf8');
    if (!layout.includes("'./styles/theme.css'") && !layout.includes('"./styles/theme.css"')) {
      add(violations, 'root layout does not import app/styles/theme.css');
    }
    if (/styles\/(?!theme\.css)[^'"\s]+\.css/.test(layout)) add(violations, 'root layout points outside app/styles/theme.css');
  } else {
    add(violations, 'root layout is missing');
  }

  const componentsConfig = path.join(siteRoot, 'components.json');
  if (await exists(componentsConfig)) {
    const config = await readFile(componentsConfig, 'utf8');
    const parsed = JSON.parse(config);
    if (parsed?.tailwind?.css !== 'app/styles/theme.css') add(violations, 'components.json does not point to app/styles/theme.css');
  }

  for (const file of sourceFiles(siteRoot, allFiles)) {
    const rel = relative(siteRoot, file);
    const content = await readFile(file, 'utf8');
    for (const token of retiredTokens) {
      const tokenPattern = new RegExp(`--${token}(?![A-Za-z0-9_-])`);
      if (tokenPattern.test(content)) add(violations, `${rel} consumes retired token --${token}`);
    }
    for (const className of retiredClasses) {
      if (consumesRetiredClass(rel, content, className)) add(violations, `${rel} consumes retired class ${className}`);
    }
  }

  for (const page of allFiles.filter((file) => /^app\/(?:.*\/)?page\.(?:tsx|ts|jsx|js)$/.test(relative(siteRoot, file)))) {
    const content = await readFile(page, 'utf8');
    const routeDirectory = path.dirname(page);
    for (const match of content.matchAll(/(?:from\s*|import\s*)["']([^"']+\.module\.css)["']/g)) {
      const importPath = match[1];
      let resolved;
      if (importPath.startsWith('@/')) resolved = path.join(siteRoot, 'src', importPath.slice(2));
      else if (importPath.startsWith('@app/')) resolved = path.join(appRoot, importPath.slice(5));
      else if (importPath.startsWith('.')) resolved = path.resolve(routeDirectory, importPath);
      else continue;
      if (path.extname(resolved) !== '.css') resolved += '.css';
      const appRelative = path.relative(appRoot, resolved);
      const isAppStylesheet = appRelative !== '' && !appRelative.startsWith(`..${path.sep}`) && !path.isAbsolute(appRelative);
      if (isAppStylesheet && path.dirname(resolved) !== routeDirectory) {
        add(violations, `${relative(siteRoot, page)} imports another route CSS Module ${relative(siteRoot, resolved)}`);
      }
    }
  }

  return violations;
}

export async function check(siteRoot = defaultSiteRoot) {
  const violations = await collectStyleBoundaryViolations(siteRoot);

  if (violations.length) {
    console.error(`Style boundary violations (${violations.length}):`);
    for (const violation of violations) console.error(`- ${violation}`);
    return false;
  }
  console.log('Style boundary is clean.');
  return true;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exitCode = (await check()) ? 0 : 1;
