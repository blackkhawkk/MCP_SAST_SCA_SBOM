# Contributing to MCP Security Server

We welcome contributions to the MCP Security Server project! This document provides guidelines for contributing.

## 🤝 How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use issue templates** when available
3. **Provide detailed information**:
   - Environment details (OS, Node.js version, Python version)
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages and logs

### Submitting Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Run the test suite**: `npm test`
7. **Commit with clear messages**
8. **Push to your fork**: `git push origin feature/amazing-feature`
9. **Open a Pull Request**

## 🔧 Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/mcp-security-server.git
cd mcp-security-server

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Start development server
npm run dev
```

## 📝 Code Style

- **TypeScript**: Use strict type checking
- **ESLint**: Follow the existing ESLint configuration
- **Prettier**: Code is auto-formatted on commit
- **Comments**: Document complex logic and security patterns

## 🧪 Testing

- Write unit tests for new security patterns
- Include integration tests for MCP protocol handlers
- Test with both valid and invalid inputs
- Verify error handling and edge cases

## 🔐 Security Considerations

- **Never commit real secrets** (use test patterns only)
- **Validate all inputs** in security analysis functions
- **Follow secure coding practices**
- **Document security implications** of changes

## 📚 Documentation

- Update README.md for new features
- Add usage examples for new tools
- Document security patterns and their detection logic
- Keep USAGE_GUIDE.md current

## 🏷️ Commit Messages

Use conventional commit format:

```
type(scope): description

feat(scanner): add new SQL injection pattern detection
fix(sbom): resolve CycloneDX format validation
docs(readme): update installation instructions
test(secrets): add AWS key detection test cases
```

## 🎯 Areas for Contribution

### High Priority
- [ ] Additional security pattern detection rules
- [ ] Performance optimizations for large codebases
- [ ] Enhanced SBOM generation features
- [ ] Better error handling and user feedback

### Medium Priority
- [ ] Support for additional programming languages
- [ ] Integration with more vulnerability databases
- [ ] Custom reporting formats
- [ ] CI/CD pipeline templates

### Documentation
- [ ] Video tutorials and demos
- [ ] Best practices guides
- [ ] Security pattern explanation documentation
- [ ] API reference documentation

## 🔄 Review Process

1. **Automated checks** must pass (tests, linting, security scans)
2. **Peer review** by at least one maintainer
3. **Security review** for changes to detection logic
4. **Documentation review** for user-facing changes

## 📜 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professional communication

## ❓ Questions?

- Open a discussion in GitHub Discussions
- Ask in issue comments
- Tag maintainers for urgent questions

Thank you for contributing to making application security more accessible! 🙏
