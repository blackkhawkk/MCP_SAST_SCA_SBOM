import { execa } from "execa";
import { writeFile, existsSync } from "fs-extra";
import path from "path";
import { parse as parseYaml } from "yaml";

export interface SBOMComponent {
  name: string;
  version: string;
  type: string;
  purl?: string;
  licenses?: string[];
  supplier?: string;
  downloadLocation?: string;
  filesAnalyzed?: boolean;
  homepage?: string;
  copyright?: string;
}

export interface SBOMResult {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{
      vendor: string;
      name: string;
      version: string;
    }>;
    component: {
      name: string;
      version: string;
      type: string;
    };
  };
  components: SBOMComponent[];
}

export class SBOMGenerator {
  async generate(
    projectPath: string,
    outputPath: string,
    format: "json" | "xml" | "spdx-json" | "spdx-xml" = "json",
    includeDevDependencies: boolean = false
  ): Promise<SBOMResult> {
    if (!existsSync(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }

    const packageJsonPath = path.join(projectPath, "package.json");
    if (!existsSync(packageJsonPath)) {
      throw new Error(`No package.json found in: ${projectPath}`);
    }

    try {
      // Try to use CycloneDX npm tool first (most comprehensive)
      return await this.generateWithCycloneDX(projectPath, outputPath, format, includeDevDependencies);
    } catch (error) {
      console.warn("CycloneDX failed, falling back to custom SBOM generation:", error);
      // Fallback to custom SBOM generation
      return await this.generateCustomSBOM(projectPath, outputPath, format, includeDevDependencies);
    }
  }

  private async generateWithCycloneDX(
    projectPath: string,
    outputPath: string,
    format: string,
    includeDevDependencies: boolean
  ): Promise<SBOMResult> {
    const args = ["cyclonedx-npm"];
    
    // Set output format
    if (format === "json") {
      args.push("--output-format", "JSON");
    } else if (format === "xml") {
      args.push("--output-format", "XML");
    }

    // Include dev dependencies
    if (!includeDevDependencies) {
      args.push("--omit", "dev");
    }

    args.push("--output-file", outputPath);

    try {
      await execa("npx", args, { cwd: projectPath });
      
      // Read and parse the generated SBOM
      const sbomContent = await import(outputPath);
      return sbomContent;
    } catch (error) {
      throw new Error(`CycloneDX SBOM generation failed: ${error}`);
    }
  }

  private async generateCustomSBOM(
    projectPath: string,
    outputPath: string,
    format: string,
    includeDevDependencies: boolean
  ): Promise<SBOMResult> {
    const packageJson = await import(path.join(projectPath, "package.json"));
    const components: SBOMComponent[] = [];

    // Get installed packages
    try {
      const result = await execa("npm", ["ls", "--json", "--depth=0"], { cwd: projectPath });
      const npmData = JSON.parse(result.stdout);

      if (npmData.dependencies) {
        for (const [name, info] of Object.entries(npmData.dependencies as Record<string, any>)) {
          components.push({
            name,
            version: info.version || "unknown",
            type: "library",
            purl: `pkg:npm/${name}@${info.version}`,
          });
        }
      }

      if (includeDevDependencies && npmData.devDependencies) {
        for (const [name, info] of Object.entries(npmData.devDependencies as Record<string, any>)) {
          components.push({
            name,
            version: info.version || "unknown",
            type: "library",
            purl: `pkg:npm/${name}@${info.version}`,
          });
        }
      }
    } catch (error) {
      console.warn("npm ls failed, using package.json dependencies:", error);
      
      // Fallback: parse dependencies from package.json
      const deps = { ...packageJson.dependencies };
      if (includeDevDependencies) {
        Object.assign(deps, packageJson.devDependencies);
      }

      for (const [name, version] of Object.entries(deps)) {
        components.push({
          name,
          version: version as string,
          type: "library",
          purl: `pkg:npm/${name}@${version}`,
        });
      }
    }

    const sbom: SBOMResult = {
      bomFormat: "CycloneDX",
      specVersion: "1.4",
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          {
            vendor: "MCP Security Server",
            name: "SBOM Generator",
            version: "1.0.0",
          },
        ],
        component: {
          name: packageJson.name || path.basename(projectPath),
          version: packageJson.version || "1.0.0",
          type: "application",
        },
      },
      components,
    };

    // Write SBOM to file
    if (format === "json" || format === "spdx-json") {
      await writeFile(outputPath, JSON.stringify(sbom, null, 2));
    } else if (format === "xml" || format === "spdx-xml") {
      // Convert to XML format (simplified)
      const xmlContent = this.convertToXML(sbom);
      await writeFile(outputPath, xmlContent);
    }

    return sbom;
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  private convertToXML(sbom: SBOMResult): string {
    // Simplified XML conversion
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n';
    xml += `  <serialNumber>${sbom.serialNumber}</serialNumber>\n`;
    xml += '  <metadata>\n';
    xml += `    <timestamp>${sbom.metadata.timestamp}</timestamp>\n`;
    xml += '    <tools>\n';
    for (const tool of sbom.metadata.tools) {
      xml += '      <tool>\n';
      xml += `        <vendor>${tool.vendor}</vendor>\n`;
      xml += `        <name>${tool.name}</name>\n`;
      xml += `        <version>${tool.version}</version>\n`;
      xml += '      </tool>\n';
    }
    xml += '    </tools>\n';
    xml += '  </metadata>\n';
    xml += '  <components>\n';
    for (const component of sbom.components) {
      xml += '    <component type="library">\n';
      xml += `      <name>${component.name}</name>\n`;
      xml += `      <version>${component.version}</version>\n`;
      if (component.purl) {
        xml += `      <purl>${component.purl}</purl>\n`;
      }
      xml += '    </component>\n';
    }
    xml += '  </components>\n';
    xml += '</bom>';
    return xml;
  }

  async analyzeSBOM(sbomPath: string): Promise<{
    componentCount: number;
    licenseDistribution: Record<string, number>;
    vulnerableComponents: string[];
    outdatedComponents: string[];
  }> {
    if (!existsSync(sbomPath)) {
      throw new Error(`SBOM file does not exist: ${sbomPath}`);
    }

    const sbomContent = await import(sbomPath);
    const sbom = sbomContent as SBOMResult;

    const analysis = {
      componentCount: sbom.components.length,
      licenseDistribution: {} as Record<string, number>,
      vulnerableComponents: [] as string[],
      outdatedComponents: [] as string[],
    };

    // Analyze licenses
    for (const component of sbom.components) {
      if (component.licenses) {
        for (const license of component.licenses) {
          analysis.licenseDistribution[license] = (analysis.licenseDistribution[license] || 0) + 1;
        }
      }
    }

    return analysis;
  }
}
