import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default [
  {
    linterOptions: {
      reportUnusedDisableDirectives: "off",
    },
  },
  {
    ignores: [
      ".standalone-stubs/**",
      "build/**",
      "coverage/**",
      "dist/**",
      "node_modules/**",
      "standalone/**",
    ],
  },
  {
    files: [
      "client/src/**/*.{ts,tsx}",
      "server/**/*.ts",
      "shared/**/*.ts",
      "vite.config.ts",
    ],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
      "react-hooks": reactHooks,
    },
    rules: {
      "react-hooks/rules-of-hooks": "error",
    },
  },
];
