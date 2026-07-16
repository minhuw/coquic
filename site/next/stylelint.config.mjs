const config = {
  extends: ['stylelint-config-standard', 'stylelint-config-tailwindcss'],
  ignoreFiles: ['.next/**', 'node_modules/**', 'out/**', 'build/**'],
  rules: {
    // Tailwind 4 directives are parsed by stylelint-config-tailwindcss; keep
    // custom project directives explicit for future CSS entry points.
    'at-rule-no-unknown': [
      true,
      {
        ignoreAtRules: [
          'apply',
          'config',
          'custom-variant',
          'plugin',
          'reference',
          'source',
          'theme',
          'utility',
          'variant',
        ],
      },
    ],
    'selector-class-pattern': [/^[a-z][a-z0-9]*(?:[-_]{1,2}[a-z0-9]+)*$/],
    // Keep the existing compatibility and token formatting conventions while
    // still checking parsing, unknown properties, and malformed values.
    'alpha-value-notation': null,
    'at-rule-empty-line-before': null,
    'color-function-notation': null,
    'color-hex-length': null,
    'custom-property-empty-line-before': null,
    'declaration-empty-line-before': null,
    'import-notation': null,
    'media-feature-range-notation': null,
    'value-keyword-case': null,
  },
  overrides: [
    {
      // Preserve the reviewed cascade in existing composed styles; new CSS
      // files retain the standard descending-specificity check.
      files: [
        'app/styles/editorial.css',
        'app/styles/evidence.css',
        'app/styles/features/blog.css',
        'app/styles/features/docs.css',
        'app/styles/features/home.css',
        'app/styles/features/interop.css',
        'app/styles/features/performance.css',
        'app/styles/features/qa.css',
        'app/styles/features/steward-dashboard.css',
        'app/styles/features/steward-planner.css',
        'app/styles/features/steward-task.css',
        'app/styles/features/transcript.css',
        'app/styles/features/workbench.css',
        'app/styles/legacy.css',
      ],
      rules: {
        'no-descending-specificity': null,
      },
    },
    {
      files: [
        'app/styles/features/qa.css',
        'app/styles/legacy.css',
        'app/styles/shell.css',
      ],
      rules: {
        'no-duplicate-selectors': null,
      },
    },
    {
      files: ['app/styles/editorial.css'],
      rules: {
        'selector-not-notation': null,
      },
    },
    {
      files: ['app/styles/foundation.css', 'app/styles/legacy.css'],
      rules: {
        'declaration-block-no-redundant-longhand-properties': null,
      },
    },
    {
      files: ['app/styles/shell.css'],
      rules: {
        'declaration-block-single-line-max-declarations': null,
      },
    },
    {
      files: ['app/styles/features/steward-task.css', 'app/styles/legacy.css'],
      rules: {
        'declaration-property-value-keyword-no-deprecated': null,
      },
    },
    {
      files: ['app/styles/foundation.css'],
      rules: {
        'font-family-name-quotes': null,
      },
    },
    {
      files: [
        'app/styles/editorial.css',
        'app/styles/evidence.css',
        'app/styles/features/interop.css',
        'app/styles/features/performance.css',
        'app/styles/features/steward-dashboard.css',
      ],
      rules: {
        'property-no-deprecated': null,
      },
    },
  ],
};

export default config;
