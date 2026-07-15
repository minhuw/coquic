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
    // Existing CSS uses BEM elements/modifiers and layered selectors whose
    // cascade order is intentional across imported feature files.
    'selector-class-pattern': [/^[a-z][a-z0-9]*(?:[-_]{1,2}[a-z0-9]+)*$/],
    'no-descending-specificity': null,
    'no-duplicate-selectors': null,
    'selector-not-notation': null,
    // Keep the existing compatibility and token formatting conventions while
    // still checking parsing, unknown properties, and malformed values.
    'alpha-value-notation': null,
    'at-rule-empty-line-before': null,
    'color-function-notation': null,
    'color-hex-length': null,
    'custom-property-empty-line-before': null,
    'declaration-block-no-redundant-longhand-properties': null,
    'declaration-block-single-line-max-declarations': null,
    'declaration-empty-line-before': null,
    'declaration-property-value-keyword-no-deprecated': null,
    'font-family-name-quotes': null,
    'import-notation': null,
    'media-feature-range-notation': null,
    'property-no-deprecated': null,
    'value-keyword-case': null,
  },
};

export default config;
