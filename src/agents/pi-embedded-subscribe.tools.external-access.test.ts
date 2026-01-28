import { describe, it, expect } from "vitest";
import { hasExternalAccessPotential } from "./pi-embedded-subscribe.tools.js";

describe("hasExternalAccessPotential", () => {
  describe("should detect external access commands", () => {
    it("detects python commands", () => {
      expect(hasExternalAccessPotential("python3 script.py")).toBe(true);
      expect(hasExternalAccessPotential("python -c 'print(1)'")).toBe(true);
      expect(hasExternalAccessPotential("python2 old_script.py")).toBe(true);
    });

    it("detects node commands", () => {
      expect(hasExternalAccessPotential("node app.js")).toBe(true);
      expect(hasExternalAccessPotential("node -e 'console.log(1)'")).toBe(true);
    });

    it("detects curl and wget", () => {
      expect(hasExternalAccessPotential("curl https://example.com")).toBe(true);
      expect(hasExternalAccessPotential("wget https://example.com/file")).toBe(true);
    });

    it("detects ssh and scp", () => {
      expect(hasExternalAccessPotential("ssh user@host")).toBe(true);
      expect(hasExternalAccessPotential("scp file user@host:")).toBe(true);
    });

    it("detects package managers", () => {
      expect(hasExternalAccessPotential("npm install lodash")).toBe(true);
      expect(hasExternalAccessPotential("pip install requests")).toBe(true);
      expect(hasExternalAccessPotential("pnpm add chalk")).toBe(true);
    });

    it("detects git network operations", () => {
      expect(hasExternalAccessPotential("git clone https://github.com/repo")).toBe(true);
      expect(hasExternalAccessPotential("git fetch origin")).toBe(true);
      expect(hasExternalAccessPotential("git pull")).toBe(true);
    });

    it("detects heredoc python scripts", () => {
      expect(
        hasExternalAccessPotential(`python3 << 'EOF'
import requests
requests.get("https://example.com")
EOF`),
      ).toBe(true);
    });
  });

  describe("should NOT detect internal commands", () => {
    it("does not flag simple shell commands", () => {
      expect(hasExternalAccessPotential("ls -la")).toBe(false);
      expect(hasExternalAccessPotential("cat file.txt")).toBe(false);
      expect(hasExternalAccessPotential("grep pattern file")).toBe(false);
      expect(hasExternalAccessPotential("echo 'hello'")).toBe(false);
    });

    it("does not flag git local operations", () => {
      expect(hasExternalAccessPotential("git status")).toBe(false);
      expect(hasExternalAccessPotential("git log")).toBe(false);
      expect(hasExternalAccessPotential("git diff")).toBe(false);
      expect(hasExternalAccessPotential("git add .")).toBe(false);
      expect(hasExternalAccessPotential("git commit -m 'msg'")).toBe(false);
    });

    it("does not flag file operations", () => {
      expect(hasExternalAccessPotential("cp src dest")).toBe(false);
      expect(hasExternalAccessPotential("mv old new")).toBe(false);
      expect(hasExternalAccessPotential("rm file")).toBe(false);
      expect(hasExternalAccessPotential("mkdir dir")).toBe(false);
    });

    it("does not flag text processing", () => {
      expect(hasExternalAccessPotential("awk '{print $1}' file")).toBe(false);
      expect(hasExternalAccessPotential("sed 's/old/new/g' file")).toBe(false);
      expect(hasExternalAccessPotential("head -10 file")).toBe(false);
      expect(hasExternalAccessPotential("tail -f log")).toBe(false);
    });
  });
});
