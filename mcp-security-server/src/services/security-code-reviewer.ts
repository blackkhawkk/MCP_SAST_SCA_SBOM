import { execa } from "execa";
import { readFile, existsSync, readdir, stat } from "fs-extra";
import path from "path";

export interface SecurityFinding {
  ruleId: string;
  severity: "info" | "warning" | "error";
  message: string;
  file: string;
  line: number;
  column: number;
  category: string;
  description: string;
  recommendation: string;
}

export interface SecurityReviewResult {
  findings: SecurityFinding[];
  summary: {
    total: number;
    error: number;
    warning: number;
    info: number;
  };
  filesCovered: string[];
  timestamp: string;
}

export class SecurityCodeReviewer {
  private securityRules = {
    // SQL Injection patterns
    "sql-injection": {
      patterns: [
        /\$\{.*\}/g, // Template literals in SQL
        /['"].*\+.*['"]/, // String concatenation
        /execute\s*\(/i,
        /query\s*\(.*\+/i,
      ],
      severity: "error" as const,
      description: "Potential SQL injection vulnerability",
      recommendation: "Use parameterized queries or prepared statements",
    },
    
    // XSS patterns
    "xss-vulnerability": {
      patterns: [
        /innerHTML\s*=/i,
        /document\.write\s*\(/i,
        /eval\s*\(/i,
        /setTimeout\s*\(\s*['"][^'"]*\+/i,
      ],
      severity: "error" as const,
      description: "Potential Cross-Site Scripting (XSS) vulnerability",
      recommendation: "Use safe DOM manipulation methods and sanitize user input",
    },

    // Command Injection
    "command-injection": {
      patterns: [
        /exec\s*\(.*\+/i,
        /spawn\s*\(.*\+/i,
        /system\s*\(/i,
      ],
      severity: "error" as const,
      description: "Potential command injection vulnerability",
      recommendation: "Avoid executing user input directly, use safe alternatives",
    },

    // Insecure Random
    "weak-random": {
      patterns: [
        /Math\.random\s*\(/i,
        /new Date\(\)\.getTime\(\)/i,
      ],
      severity: "warning" as const,
      description: "Weak random number generation",
      recommendation: "Use cryptographically secure random number generators",
    },

    // Hardcoded secrets
    "hardcoded-secrets": {
      patterns: [
        /password\s*[:=]\s*['"][^'"]+['"]/i,
        /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i,
        /secret\s*[:=]\s*['"][^'"]+['"]/i,
        /token\s*[:=]\s*['"][^'"]+['"]/i,
      ],
      severity: "error" as const,
      description: "Potential hardcoded secret or credential",
      recommendation: "Store secrets in environment variables or secure key management",
    },

    // Insecure HTTP
    "insecure-http": {
      patterns: [
        /http:\/\/[^'"]+/g,
        /secure\s*:\s*false/i,
      ],
      severity: "warning" as const,
      description: "Insecure HTTP usage",
      recommendation: "Use HTTPS for all communications",
    },

    // Path traversal
    "path-traversal": {
      patterns: [
        /\.\.\//g,
        /path\.join\s*\(.*req\./i,
        /fs\.readFile\s*\(.*req\./i,
      ],
      severity: "error" as const,
      description: "Potential path traversal vulnerability",
      recommendation: "Validate and sanitize file paths, use path.resolve()",
    },

    // Insecure cookies
    "insecure-cookies": {
      patterns: [
        /httpOnly\s*:\s*false/i,
        /secure\s*:\s*false/i,
        /sameSite\s*:\s*['"]?none['"]?/i,
      ],
      severity: "warning" as const,
      description: "Insecure cookie configuration",
      recommendation: "Set httpOnly, secure, and sameSite attributes appropriately",
    },

    // Unsafe deserialization
    "unsafe-deserialization": {
      patterns: [
        /JSON\.parse\s*\(.*req\./i,
        /eval\s*\(.*JSON/i,
        /Function\s*\(/i,
      ],
      severity: "error" as const,
      description: "Potential unsafe deserialization",
      recommendation: "Validate input before deserialization, avoid eval()",
    },
  };

  async review(
    filePath: string,
    specificRules?: string[],
    minSeverity: "info" | "warning" | "error" = "warning"
  ): Promise<SecurityReviewResult> {
    if (!existsSync(filePath)) {
      throw new Error(`File or directory does not exist: ${filePath}`);
    }

    const findings: SecurityFinding[] = [];
    const filesCovered: string[] = [];

    const stats = await stat(filePath);
    if (stats.isDirectory()) {
      await this.reviewDirectory(filePath, findings, filesCovered, specificRules, minSeverity);
    } else {
      await this.reviewFile(filePath, findings, filesCovered, specificRules, minSeverity);
    }

    const summary = {
      total: findings.length,
      error: findings.filter(f => f.severity === "error").length,
      warning: findings.filter(f => f.severity === "warning").length,
      info: findings.filter(f => f.severity === "info").length,
    };

    return {
      findings,
      summary,
      filesCovered,
      timestamp: new Date().toISOString(),
    };
  }

  private async reviewDirectory(
    dirPath: string,
    findings: SecurityFinding[],
    filesCovered: string[],
    specificRules?: string[],
    minSeverity: "info" | "warning" | "error" = "warning"
  ): Promise<void> {
    const entries = await readdir(dirPath);

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      const stats = await stat(fullPath);

      if (stats.isDirectory()) {
        // Skip node_modules and other common directories
        if (!["node_modules", ".git", "build", "dist", "coverage"].includes(entry)) {
          await this.reviewDirectory(fullPath, findings, filesCovered, specificRules, minSeverity);
        }
      } else if (this.shouldReviewFile(fullPath)) {
        await this.reviewFile(fullPath, findings, filesCovered, specificRules, minSeverity);
      }
    }
  }

  private shouldReviewFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return [".js", ".ts", ".jsx", ".tsx", ".vue", ".php", ".py", ".java", ".cs"].includes(ext);
  }

  private async reviewFile(
    filePath: string,
    findings: SecurityFinding[],
    filesCovered: string[],
    specificRules?: string[],
    minSeverity: "info" | "warning" | "error" = "warning"
  ): Promise<void> {
    try {
      const content = await readFile(filePath, "utf-8");
      const lines = content.split("\n");
      filesCovered.push(filePath);

      const rulesToCheck = specificRules || Object.keys(this.securityRules);

      for (const ruleId of rulesToCheck) {
        const rule = this.securityRules[ruleId as keyof typeof this.securityRules];
        if (!rule || !this.shouldIncludeSeverity(rule.severity, minSeverity)) {
          continue;
        }

        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
          const line = lines[lineNum];
          
          for (const pattern of rule.patterns) {
            const matches = line.match(pattern);
            if (matches) {
              findings.push({
                ruleId,
                severity: rule.severity,
                message: rule.description,
                file: filePath,
                line: lineNum + 1,
                column: line.indexOf(matches[0]) + 1,
                category: this.getCategoryFromRuleId(ruleId),
                description: rule.description,
                recommendation: rule.recommendation,
              });
            }
          }
        }
      }
    } catch (error) {
      console.warn(`Failed to review file ${filePath}:`, error);
    }
  }

  private shouldIncludeSeverity(
    severity: "info" | "warning" | "error",
    minSeverity: "info" | "warning" | "error"
  ): boolean {
    const severityLevels = { info: 0, warning: 1, error: 2 };
    return severityLevels[severity] >= severityLevels[minSeverity];
  }

  private getCategoryFromRuleId(ruleId: string): string {
    if (ruleId.includes("sql")) return "SQL Injection";
    if (ruleId.includes("xss")) return "Cross-Site Scripting";
    if (ruleId.includes("command")) return "Command Injection";
    if (ruleId.includes("random")) return "Cryptography";
    if (ruleId.includes("secret")) return "Authentication";
    if (ruleId.includes("http")) return "Transport Security";
    if (ruleId.includes("path")) return "Path Traversal";
    if (ruleId.includes("cookie")) return "Session Management";
    if (ruleId.includes("deserialization")) return "Deserialization";
    return "Security";
  }

  async generateReport(result: SecurityReviewResult, format: "json" | "html" | "markdown" = "json"): Promise<string> {
    switch (format) {
      case "json":
        return JSON.stringify(result, null, 2);
      
      case "markdown":
        return this.generateMarkdownReport(result);
      
      case "html":
        return this.generateHtmlReport(result);
      
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  private generateMarkdownReport(result: SecurityReviewResult): string {
    let report = "# Security Code Review Report\n\n";
    report += `**Generated:** ${result.timestamp}\n`;
    report += `**Files Reviewed:** ${result.filesCovered.length}\n\n`;
    
    report += "## Summary\n\n";
    report += `- **Total Issues:** ${result.summary.total}\n`;
    report += `- **Errors:** ${result.summary.error}\n`;
    report += `- **Warnings:** ${result.summary.warning}\n`;
    report += `- **Info:** ${result.summary.info}\n\n`;

    if (result.findings.length > 0) {
      report += "## Findings\n\n";
      for (const finding of result.findings) {
        report += `### ${finding.severity.toUpperCase()}: ${finding.message}\n\n`;
        report += `**File:** ${finding.file}:${finding.line}:${finding.column}\n`;
        report += `**Category:** ${finding.category}\n`;
        report += `**Rule:** ${finding.ruleId}\n\n`;
        report += `**Description:** ${finding.description}\n\n`;
        report += `**Recommendation:** ${finding.recommendation}\n\n`;
        report += "---\n\n";
      }
    }

    return report;
  }

  private generateHtmlReport(result: SecurityReviewResult): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Code Review Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; margin: 20px 0; }
        .finding { border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; }
        .error { border-left-color: #e74c3c; }
        .warning { border-left-color: #f39c12; }
        .info { border-left-color: #3498db; }
    </style>
</head>
<body>
    <h1>Security Code Review Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Generated:</strong> ${result.timestamp}</p>
        <p><strong>Files Reviewed:</strong> ${result.filesCovered.length}</p>
        <p><strong>Total Issues:</strong> ${result.summary.total}</p>
        <p><strong>Errors:</strong> ${result.summary.error}</p>
        <p><strong>Warnings:</strong> ${result.summary.warning}</p>
        <p><strong>Info:</strong> ${result.summary.info}</p>
    </div>
    
    <h2>Findings</h2>
    ${result.findings.map(finding => `
        <div class="finding ${finding.severity}">
            <h3>${finding.severity.toUpperCase()}: ${finding.message}</h3>
            <p><strong>File:</strong> ${finding.file}:${finding.line}:${finding.column}</p>
            <p><strong>Category:</strong> ${finding.category}</p>
            <p><strong>Rule:</strong> ${finding.ruleId}</p>
            <p><strong>Description:</strong> ${finding.description}</p>
            <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
        </div>
    `).join('')}
</body>
</html>`;
  }
}
