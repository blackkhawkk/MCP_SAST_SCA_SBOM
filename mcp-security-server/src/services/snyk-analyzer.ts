import { execa } from "execa";
import { existsSync } from "fs";
import path from "path";

export interface SnykTestOptions {
  severity?: "low" | "medium" | "high" | "critical";
  packageManager?: "npm" | "yarn" | "pnpm";
  outputFormat?: "json" | "table" | "sarif";
  includeDev?: boolean;
}

export interface SnykVulnerability {
  id: string;
  title: string;
  description: string;
  severity: string;
  cvssScore: number;
  packageName: string;
  version: string;
  upgradePath: string[];
  references: string[];
}

export interface SnykTestResult {
  vulnerabilities: SnykVulnerability[];
  summary: {
    total: number;
    high: number;
    medium: number;
    low: number;
    critical: number;
  };
  projectName: string;
  projectPath: string;
  timestamp: string;
}

export class SnykAnalyzer {
  private async isSnykInstalled(): Promise<boolean> {
    try {
      await execa("snyk", ["--version"]);
      return true;
    } catch {
      return false;
    }
  }

  private async authenticateSnyk(): Promise<boolean> {
    try {
      const result = await execa("snyk", ["auth", "--print-token"]);
      return result.exitCode === 0;
    } catch {
      return false;
    }
  }

  async runTest(projectPath: string, options: SnykTestOptions = {}): Promise<SnykTestResult> {
    if (!existsSync(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }

    if (!(await this.isSnykInstalled())) {
      throw new Error("Snyk CLI is not installed. Please install it with: npm install -g snyk");
    }

    if (!(await this.authenticateSnyk())) {
      throw new Error("Snyk is not authenticated. Please run: snyk auth");
    }

    const args = ["test", projectPath];

    // Add severity filter
    if (options.severity) {
      args.push("--severity-threshold", options.severity);
    }

    // Add package manager option
    if (options.packageManager) {
      args.push("--package-manager", options.packageManager);
    }

    // Add output format
    if (options.outputFormat === "json") {
      args.push("--json");
    } else if (options.outputFormat === "sarif") {
      args.push("--sarif");
    }

    // Include dev dependencies
    if (options.includeDev) {
      args.push("--dev");
    }

    try {
      const result = await execa("snyk", args, {
        cwd: projectPath,
        reject: false, // Don't reject on non-zero exit codes
      });

      if (options.outputFormat === "json" || !options.outputFormat) {
        const data = JSON.parse(result.stdout);
        return this.parseSnykResults(data, projectPath);
      } else {
        // For table or sarif format, return raw output
        return {
          vulnerabilities: [],
          summary: { total: 0, high: 0, medium: 0, low: 0, critical: 0 },
          projectName: path.basename(projectPath),
          projectPath,
          timestamp: new Date().toISOString(),
          rawOutput: result.stdout,
        } as any;
      }
    } catch (error) {
      throw new Error(`Snyk test failed: ${error}`);
    }
  }

  private parseSnykResults(data: any, projectPath: string): SnykTestResult {
    const vulnerabilities: SnykVulnerability[] = [];
    const summary = { total: 0, high: 0, medium: 0, low: 0, critical: 0 };

    if (data.vulnerabilities) {
      for (const vuln of data.vulnerabilities) {
        vulnerabilities.push({
          id: vuln.id,
          title: vuln.title,
          description: vuln.description || "",
          severity: vuln.severity,
          cvssScore: vuln.cvssScore || 0,
          packageName: vuln.packageName,
          version: vuln.version,
          upgradePath: vuln.upgradePath || [],
          references: vuln.references || [],
        });

        summary.total++;
        switch (vuln.severity.toLowerCase()) {
          case "critical":
            summary.critical++;
            break;
          case "high":
            summary.high++;
            break;
          case "medium":
            summary.medium++;
            break;
          case "low":
            summary.low++;
            break;
        }
      }
    }

    return {
      vulnerabilities,
      summary,
      projectName: path.basename(projectPath),
      projectPath,
      timestamp: new Date().toISOString(),
    };
  }

  async runContainerScan(imageName: string): Promise<SnykTestResult> {
    if (!(await this.isSnykInstalled())) {
      throw new Error("Snyk CLI is not installed");
    }

    try {
      const result = await execa("snyk", ["container", "test", imageName, "--json"]);
      const data = JSON.parse(result.stdout);
      return this.parseSnykResults(data, imageName);
    } catch (error) {
      throw new Error(`Snyk container scan failed: ${error}`);
    }
  }

  async runCodeScan(projectPath: string): Promise<SnykTestResult> {
    if (!(await this.isSnykInstalled())) {
      throw new Error("Snyk CLI is not installed");
    }

    try {
      const result = await execa("snyk", ["code", "test", projectPath, "--json"]);
      const data = JSON.parse(result.stdout);
      return this.parseSnykResults(data, projectPath);
    } catch (error) {
      throw new Error(`Snyk code scan failed: ${error}`);
    }
  }
}
