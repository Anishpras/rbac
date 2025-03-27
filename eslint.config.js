export default [
  {
    ignores: ["dist/**", "node_modules/**"],
  },
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parser: await (async () => {
        const { default: typescriptParser } = await import('@typescript-eslint/parser');
        return typescriptParser;
      })(),
      parserOptions: {
        project: './tsconfig.json',
      },
    },
    plugins: {
      '@typescript-eslint': await (async () => {
        const { default: typescriptPlugin } = await import('@typescript-eslint/eslint-plugin');
        return typescriptPlugin;
      })(),
    },
    rules: {
      // Base ESLint rules
      'no-console': 'warn',
      'no-unused-vars': 'off', // TypeScript handles this
      
      // TypeScript specific rules
      '@typescript-eslint/no-unused-vars': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  }
];
