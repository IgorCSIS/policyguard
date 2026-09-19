import { defineConfig } from "vite";

/**
 * Vite config.
 *
 * `base` has to match the repository name for GitHub Pages. Deploying to
 * <user>.github.io/<repo> means every asset URL carries that prefix, and
 * getting it wrong produces a page that works locally and 404s in production.
 */
export default defineConfig({
  base: "/policyguard/",
  build: { target: "es2022" },
});
