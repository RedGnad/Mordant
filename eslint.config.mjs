import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTypeScript,
  globalIgnores([
    ".next/**",
    ".cleanverse-test-dist/**",
    ".product-test-dist/**",
    "contracts/lib/**",
    "contracts/out/**",
    "contracts/cache/**",
  ]),
  {
    // CommonJS by necessity, not by preference: these files are loaded synchronously by
    // CommonJS test code, so `require` is the only module system available to them.
    // Only this one rule is lifted, and only for those files; everything else still
    // applies, and no application module is covered.
    files: ["**/*.cjs", "test/stubs/**/*.js"],
    rules: { "@typescript-eslint/no-require-imports": "off" },
  },
]);
