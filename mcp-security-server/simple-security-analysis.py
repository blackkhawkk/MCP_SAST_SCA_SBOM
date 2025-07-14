#!/usr/bin/env python3
"""
Simple Security Analysis Script for OWASP Juice Shop
This script provides basic security analysis capabilities without requiring Node.js
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import re

# Configuration
JUICE_SHOP_PATH = r"e:\R&D\juice-shop\juice-shop_18.0.0"
REPORTS_DIR = "security-reports"
MCP_SERVER_DIR = r"e:\R&D\juice-shop\mcp-security-server"

class SimpleSecurityAnalyzer:
    def __init__(self):
        self.reports_dir = Path(REPORTS_DIR)
        self.reports_dir.mkdir(exist_ok=True)
        self.juice_shop_path = Path(JUICE_SHOP_PATH)
        
    def analyze_package_json(self):
        """Analyze package.json for dependency information"""
        print("📦 Analyzing package.json dependencies...")
        
        package_json_path = self.juice_shop_path / "package.json"
        if not package_json_path.exists():
            return {"error": "package.json not found"}
            
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
                
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            analysis = {
                "metadata": {
                    "name": package_data.get('name', 'unknown'),
                    "version": package_data.get('version', 'unknown'),
                    "description": package_data.get('description', ''),
                    "analysis_date": datetime.now().isoformat()
                },
                "dependencies": {
                    "production": len(dependencies),
                    "development": len(dev_dependencies),
                    "total": len(dependencies) + len(dev_dependencies)
                },
                "dependency_list": {
                    "production": dependencies,
                    "development": dev_dependencies
                }
            }
            
            return analysis
            
        except Exception as e:
            return {"error": f"Failed to analyze package.json: {str(e)}"}
    
    def analyze_existing_sbom(self):
        """Analyze existing SBOM files if available"""
        print("📋 Checking for existing SBOM files...")
        
        sbom_files = ['bom.json', 'bom.xml']
        sbom_analysis = {}
        
        for sbom_file in sbom_files:
            sbom_path = self.juice_shop_path / sbom_file
            if sbom_path.exists():
                print(f"   Found: {sbom_file}")
                try:
                    if sbom_file.endswith('.json'):
                        with open(sbom_path, 'r', encoding='utf-8') as f:
                            sbom_data = json.load(f)
                            
                        components = sbom_data.get('components', [])
                        sbom_analysis[sbom_file] = {
                            "format": "CycloneDX JSON",
                            "version": sbom_data.get('version', 'unknown'),
                            "components_count": len(components),
                            "serial_number": sbom_data.get('serialNumber', ''),
                            "metadata": sbom_data.get('metadata', {})
                        }
                    else:
                        # For XML, just get basic info
                        file_size = sbom_path.stat().st_size
                        sbom_analysis[sbom_file] = {
                            "format": "CycloneDX XML",
                            "file_size": file_size,
                            "exists": True
                        }
                        
                except Exception as e:
                    sbom_analysis[sbom_file] = {"error": f"Failed to parse: {str(e)}"}
            else:
                print(f"   Not found: {sbom_file}")
                
        return sbom_analysis
    
    def scan_for_secrets(self):
        """Basic secrets scanning using regex patterns"""
        print("🔐 Scanning for potential secrets...")
        
        secret_patterns = {
            "api_key": r"api[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
            "password": r"password\s*[=:]\s*['\"]?([^'\"\s]{8,})['\"]?",
            "secret": r"secret\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?",
            "token": r"token\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
            "private_key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
        }
        
        findings = []
        
        # Scan common files
        scan_files = [
            "config/*.yml",
            "config/*.yaml", 
            "config/*.json",
            "*.js",
            "*.ts",
            "*.env*"
        ]
        
        try:
            for pattern in scan_files:
                files = list(self.juice_shop_path.glob(pattern))
                for file_path in files:
                    if file_path.is_file():
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            for secret_type, regex_pattern in secret_patterns.items():
                                matches = re.finditer(regex_pattern, content, re.IGNORECASE)
                                for match in matches:
                                    findings.append({
                                        "type": secret_type,
                                        "file": str(file_path.relative_to(self.juice_shop_path)),
                                        "line": content[:match.start()].count('\n') + 1,
                                        "pattern_matched": True,
                                        "severity": "high" if secret_type in ["private_key", "aws_secret_key"] else "medium"
                                    })
                                    
                        except Exception as e:
                            print(f"   Error scanning {file_path}: {e}")
                            
        except Exception as e:
            print(f"   Error during secrets scan: {e}")
            
        return {
            "summary": {
                "total": len(findings),
                "high": len([f for f in findings if f['severity'] == 'high']),
                "medium": len([f for f in findings if f['severity'] == 'medium'])
            },
            "findings": findings
        }
    
    def analyze_source_code_patterns(self):
        """Basic static analysis for common security patterns"""
        print("🔍 Analyzing source code for security patterns...")
        
        security_patterns = {
            "sql_injection": r"(query|execute)\s*\(\s*['\"`].*\+.*['\"`]",
            "xss_vulnerable": r"innerHTML\s*=\s*.*\+",
            "eval_usage": r"\beval\s*\(",
            "command_injection": r"exec\s*\(\s*.*\+",
            "path_traversal": r"(\.\.\/|\.\.\\)",
            "hardcoded_url": r"http[s]?://[a-zA-Z0-9.-]+",
            "console_log": r"console\.(log|debug|info)",
            "todo_fixme": r"(TODO|FIXME|HACK):"
        }
        
        findings = []
        
        # Scan TypeScript and JavaScript files
        for ext in ['*.ts', '*.js']:
            files = list(self.juice_shop_path.rglob(ext))
            for file_path in files:
                if 'node_modules' in str(file_path) or 'build' in str(file_path):
                    continue
                    
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    for pattern_name, regex_pattern in security_patterns.items():
                        matches = re.finditer(regex_pattern, content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                "pattern": pattern_name,
                                "file": str(file_path.relative_to(self.juice_shop_path)),
                                "line": line_num,
                                "match": match.group(0)[:100],  # Truncate long matches
                                "severity": self.get_pattern_severity(pattern_name)
                            })
                            
                except Exception as e:
                    print(f"   Error scanning {file_path}: {e}")
                    
        return {
            "summary": {
                "total": len(findings),
                "high": len([f for f in findings if f['severity'] == 'high']),
                "medium": len([f for f in findings if f['severity'] == 'medium']),
                "low": len([f for f in findings if f['severity'] == 'low'])
            },
            "findings": findings
        }
    
    def get_pattern_severity(self, pattern_name):
        """Determine severity based on pattern type"""
        high_risk = ['sql_injection', 'command_injection', 'eval_usage']
        medium_risk = ['xss_vulnerable', 'path_traversal']
        
        if pattern_name in high_risk:
            return 'high'
        elif pattern_name in medium_risk:
            return 'medium'
        else:
            return 'low'
    
    def generate_report(self, analysis_results):
        """Generate comprehensive security report"""
        print("📊 Generating comprehensive security report...")
        
        report = {
            "metadata": {
                "project_name": "OWASP Juice Shop",
                "project_path": str(self.juice_shop_path),
                "analysis_date": datetime.now().isoformat(),
                "analyzer": "Simple Security Analyzer (Python)",
                "version": "1.0.0"
            },
            "summary": {
                "dependencies_analyzed": analysis_results['dependencies']['dependencies']['total'],
                "secrets_found": analysis_results['secrets']['summary']['total'],
                "code_issues_found": analysis_results['code_analysis']['summary']['total'],
                "sbom_files_found": len([k for k, v in analysis_results['sbom'].items() if not v.get('error')]),
                "risk_score": self.calculate_risk_score(analysis_results)
            },
            "detailed_results": analysis_results,
            "recommendations": self.generate_recommendations(analysis_results)
        }
        
        return report
    
    def calculate_risk_score(self, results):
        """Calculate overall risk score (1-10)"""
        score = 0
        
        # Factor in secrets
        secrets_score = min(results['secrets']['summary']['total'] * 2, 4)
        
        # Factor in code issues
        code_score = min(results['code_analysis']['summary']['high'] * 2 + 
                        results['code_analysis']['summary']['medium'] * 1, 4)
        
        # Factor in dependency count (more deps = potentially more risk)
        deps_score = min(results['dependencies']['dependencies']['total'] / 50, 2)
        
        total_score = secrets_score + code_score + deps_score
        return min(round(total_score), 10)
    
    def generate_recommendations(self, results):
        """Generate actionable recommendations"""
        recommendations = []
        
        if results['secrets']['summary']['total'] > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Secrets Management",
                "issue": f"Found {results['secrets']['summary']['total']} potential secrets in code",
                "action": "Remove hardcoded secrets and use environment variables or secret management systems"
            })
        
        if results['code_analysis']['summary']['high'] > 0:
            recommendations.append({
                "priority": "HIGH", 
                "category": "Code Security",
                "issue": f"Found {results['code_analysis']['summary']['high']} high-risk code patterns",
                "action": "Review and fix high-risk security patterns (SQL injection, command injection, eval usage)"
            })
        
        if results['dependencies']['dependencies']['total'] > 100:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Dependency Management", 
                "issue": f"Large number of dependencies ({results['dependencies']['dependencies']['total']})",
                "action": "Consider dependency auditing and vulnerability scanning with tools like npm audit or Snyk"
            })
        
        # Always include these general recommendations
        recommendations.extend([
            {
                "priority": "MEDIUM",
                "category": "Security Process",
                "issue": "No automated security scanning detected",
                "action": "Integrate security scanning into CI/CD pipeline"
            },
            {
                "priority": "LOW",
                "category": "Monitoring",
                "issue": "Security monitoring setup",
                "action": "Implement security monitoring and logging for production deployment"
            }
        ])
        
        return recommendations
    
    def save_report(self, filename, data):
        """Save report to file"""
        filepath = self.reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"   Report saved: {filepath}")
    
    def run_analysis(self):
        """Run complete security analysis"""
        print("🔍 Starting Simple Security Analysis for OWASP Juice Shop\n")
        
        if not self.juice_shop_path.exists():
            print(f"❌ Error: Juice Shop path not found: {self.juice_shop_path}")
            return
        
        try:
            # Run all analysis components
            dependencies = self.analyze_package_json()
            sbom = self.analyze_existing_sbom()
            secrets = self.scan_for_secrets()
            code_analysis = self.analyze_source_code_patterns()
            
            # Combine results
            analysis_results = {
                'dependencies': dependencies,
                'sbom': sbom,
                'secrets': secrets,
                'code_analysis': code_analysis
            }
            
            # Generate comprehensive report
            comprehensive_report = self.generate_report(analysis_results)
            
            # Save individual reports
            self.save_report('dependencies-analysis.json', dependencies)
            self.save_report('sbom-analysis.json', sbom)
            self.save_report('secrets-scan.json', secrets)
            self.save_report('code-analysis.json', code_analysis)
            self.save_report('comprehensive-security-report.json', comprehensive_report)
            
            # Print summary
            print(f"\n✅ Analysis Complete!")
            print(f"📈 Security Summary:")
            print(f"   Dependencies: {comprehensive_report['summary']['dependencies_analyzed']} total")
            print(f"   Secrets Found: {comprehensive_report['summary']['secrets_found']}")
            print(f"   Code Issues: {comprehensive_report['summary']['code_issues_found']}")
            print(f"   SBOM Files: {comprehensive_report['summary']['sbom_files_found']}")
            print(f"   Risk Score: {comprehensive_report['summary']['risk_score']}/10")
            print(f"\n📊 Reports saved to: {self.reports_dir}")
            
            # Show key recommendations
            print(f"\n🔧 Key Recommendations:")
            for rec in comprehensive_report['recommendations'][:3]:
                print(f"   [{rec['priority']}] {rec['category']}: {rec['action']}")
                
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()

def main():
    analyzer = SimpleSecurityAnalyzer()
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
