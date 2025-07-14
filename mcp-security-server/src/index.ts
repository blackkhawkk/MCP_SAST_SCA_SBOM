#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { SnykAnalyzer } from "./services/snyk-analyzer.js";
import { SBOMGenerator } from "./services/sbom-generator.js";
import { SecurityCodeReviewer } from "./services/security-code-reviewer.js";
import { VulnerabilityScanner } from "./services/vulnerability-scanner.js";

// Tool schemas
const SnykTestSchema = z.object({
  projectPath: z.string().describe("Path to the project to test"),
  options: z.object({
    severity: z.enum(["low", "medium", "high", "critical"]).optional(),
    packageManager: z.enum(["npm", "yarn", "pnpm"]).optional(),
    outputFormat: z.enum(["json", "table", "sarif"]).optional(),
    includeDev: z.boolean().optional().default(false),
  }).optional().default({}),
});

const GenerateSBOMSchema = z.object({
  projectPath: z.string().describe("Path to the project"),
  outputPath: z.string().describe("Path where to save the SBOM"),
  format: z.enum(["json", "xml", "spdx-json", "spdx-xml"]).default("json"),
  includeDevDependencies: z.boolean().default(false),
});

const SecurityCodeReviewSchema = z.object({
  filePath: z.string().describe("Path to the file or directory to review"),
  rules: z.array(z.string()).optional().describe("Specific security rules to check"),
  severity: z.enum(["info", "warning", "error"]).optional().default("warning"),
});

const VulnerabilityScanSchema = z.object({
  target: z.string().describe("Target to scan (file, directory, or URL)"),
  scanType: z.enum(["sca", "sast", "secrets", "iac", "container"]).describe("Type of scan to perform"),
  outputFormat: z.enum(["json", "sarif", "table"]).default("json"),
});

class MCPSecurityServer {
  private server: Server;
  private snykAnalyzer: SnykAnalyzer;
  private sbomGenerator: SBOMGenerator;
  private securityCodeReviewer: SecurityCodeReviewer;
  private vulnerabilityScanner: VulnerabilityScanner;

  constructor() {
    this.server = new Server(
      {
        name: "security-analyzer",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.snykAnalyzer = new SnykAnalyzer();
    this.sbomGenerator = new SBOMGenerator();
    this.securityCodeReviewer = new SecurityCodeReviewer();
    this.vulnerabilityScanner = new VulnerabilityScanner();

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "snyk_test",
            description: "Run Snyk vulnerability test on a project",
            inputSchema: {
              type: "object",
              properties: {
                projectPath: {
                  type: "string",
                  description: "Path to the project to test",
                },
                options: {
                  type: "object",
                  properties: {
                    severity: {
                      type: "string",
                      enum: ["low", "medium", "high", "critical"],
                      description: "Filter by vulnerability severity",
                    },
                    packageManager: {
                      type: "string",
                      enum: ["npm", "yarn", "pnpm"],
                      description: "Package manager to use",
                    },
                    outputFormat: {
                      type: "string",
                      enum: ["json", "table", "sarif"],
                      description: "Output format for results",
                    },
                    includeDev: {
                      type: "boolean",
                      description: "Include development dependencies",
                      default: false,
                    },
                  },
                },
              },
              required: ["projectPath"],
            },
          },
          {
            name: "generate_sbom",
            description: "Generate Software Bill of Materials (SBOM) for a project",
            inputSchema: {
              type: "object",
              properties: {
                projectPath: {
                  type: "string",
                  description: "Path to the project",
                },
                outputPath: {
                  type: "string",
                  description: "Path where to save the SBOM",
                },
                format: {
                  type: "string",
                  enum: ["json", "xml", "spdx-json", "spdx-xml"],
                  default: "json",
                  description: "SBOM format",
                },
                includeDevDependencies: {
                  type: "boolean",
                  default: false,
                  description: "Include development dependencies",
                },
              },
              required: ["projectPath", "outputPath"],
            },
          },
          {
            name: "security_code_review",
            description: "Perform security-focused code review",
            inputSchema: {
              type: "object",
              properties: {
                filePath: {
                  type: "string",
                  description: "Path to the file or directory to review",
                },
                rules: {
                  type: "array",
                  items: { type: "string" },
                  description: "Specific security rules to check",
                },
                severity: {
                  type: "string",
                  enum: ["info", "warning", "error"],
                  default: "warning",
                  description: "Minimum severity level to report",
                },
              },
              required: ["filePath"],
            },
          },
          {
            name: "vulnerability_scan",
            description: "Comprehensive vulnerability scanning",
            inputSchema: {
              type: "object",
              properties: {
                target: {
                  type: "string",
                  description: "Target to scan (file, directory, or URL)",
                },
                scanType: {
                  type: "string",
                  enum: ["sca", "sast", "secrets", "iac", "container"],
                  description: "Type of scan to perform",
                },
                outputFormat: {
                  type: "string",
                  enum: ["json", "sarif", "table"],
                  default: "json",
                  description: "Output format for results",
                },
              },
              required: ["target", "scanType"],
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const { name, arguments: args } = request.params;

        switch (name) {
          case "snyk_test": {
            const params = SnykTestSchema.parse(args);
            const result = await this.snykAnalyzer.runTest(params.projectPath, params.options);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case "generate_sbom": {
            const params = GenerateSBOMSchema.parse(args);
            const result = await this.sbomGenerator.generate(
              params.projectPath,
              params.outputPath,
              params.format,
              params.includeDevDependencies
            );
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case "security_code_review": {
            const params = SecurityCodeReviewSchema.parse(args);
            const result = await this.securityCodeReviewer.review(
              params.filePath,
              params.rules,
              params.severity
            );
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case "vulnerability_scan": {
            const params = VulnerabilityScanSchema.parse(args);
            const result = await this.vulnerabilityScanner.scan(
              params.target,
              params.scanType,
              params.outputFormat
            );
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Invalid parameters: ${error.message}`
          );
        }
        throw error;
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("MCP Security Server running on stdio");
  }
}

const server = new MCPSecurityServer();
server.run().catch(console.error);
