import love from 'eslint-config-love'
import stylistic from '@stylistic/eslint-plugin'

const tsFiles = ['**/*.ts']

export default [
  // FORMATTING RULES
  {
    ...stylistic.configs.recommended,
    files: tsFiles
  },
  {
    files: tsFiles,
    rules: {
      '@stylistic/arrow-parens': ['error', 'as-needed'],
      '@stylistic/brace-style': ['error', '1tbs', { allowSingleLine: true }],
      '@stylistic/comma-dangle': ['error', 'never'],
      '@stylistic/indent': ['error', 2, { ignoreComments: true }],
      '@stylistic/max-statements-per-line': ['error', { max: 3 }],
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true }],
      '@stylistic/quote-props': ['error', 'as-needed'],
      '@stylistic/space-before-function-paren': ['error', 'always'],
      '@stylistic/type-annotation-spacing': 'error',
      '@stylistic/type-generic-spacing': 'error'
    }
  },
  // STRUCTURAL RULES
  {
    ...love,
    files: tsFiles
  },
  {
    files: tsFiles,
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: './tsconfig.eslint.json'
      }
    },
    rules: {
      '@typescript-eslint/array-type': ['error', { default: 'array' }],
      '@typescript-eslint/class-methods-use-this': 'off', // sometimes methods are on a class for good organization
      '@typescript-eslint/explicit-function-return-type': 'off', // useless boilerplate
      '@typescript-eslint/init-declarations': 'off',
      '@typescript-eslint/no-explicit-any': 'off', // no-unsafe-* rules catch dangerous usage
      '@typescript-eslint/no-magic-numbers': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off', // would have disabled using ! to mark something as non-null,
                                                         // generally not avoidable without wasting cpu cycles on a check
      '@typescript-eslint/no-unsafe-type-assertion': 'off', // we only assert types when we know what we're doing
      '@typescript-eslint/no-unused-vars': 'off', // typescript already reports this and VSCode darkens the variable
      '@typescript-eslint/prefer-destructuring': 'off', // no reason to force destructuring
      '@typescript-eslint/prefer-nullish-coalescing': ['error', { ignoreConditionalTests: true, ignorePrimitives: { bigint: false, boolean: false, number: false, string: true } }],
      '@typescript-eslint/prefer-readonly': 'off', // readonly adds a lot of complication and often infects other code with its complexity
      '@typescript-eslint/require-await': 'off', // async without await is intentional for future-proofing public APIs
      '@typescript-eslint/restrict-template-expressions': ['error', { allowAny: true }], // `${myVar}` is fine if myVar is `any`
      '@typescript-eslint/strict-boolean-expressions': 'off', // we know how truthiness works, annoying to have to avoid
      complexity: 'off', // complexity is a judgment call, not a number
      eqeqeq: ['error', 'always', { null: 'ignore' }], // == null is best practice for null/undefined checks
      'max-depth': 'off',
      'no-await-in-loop': 'off', // sequential awaits are often intentional to avoid overwhelming a resource
      'no-negated-condition': 'off',
      // no-param-reassign is off because this is a fastify plugin codebase where mutating
      // req/res properties is the standard pattern - do not blindly copy into other repos
      'no-param-reassign': 'off',
      'no-plusplus': ['error', { allowForLoopAfterthoughts: true }],
      'prefer-named-capture-group': 'off',
      'prefer-template': 'off',
      'promise/avoid-new': 'off', // sometimes you need to wrap callback APIs
      'require-atomic-updates': 'off' // false positives in request handler context
    }
  },
  // RELAXED RULES FOR TEST FILES
  {
    files: ['test/**/*.ts', 'testserver/**/*.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-unsafe-type-assertion': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/unbound-method': 'off'
    }
  }
]
