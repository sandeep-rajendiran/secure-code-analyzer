# 🛡️ Secure Code Analyzer - DevSecOps Integration Platform

An enterprise-grade DevSecOps platform that integrates security analysis, code quality assessment, and automated remediation into CI/CD pipelines with comprehensive reporting and real-time monitoring.

## 🚀 Features

### 🔍 Security Analysis
- **Multi-Language Support**: JavaScript, TypeScript, Python, Java, Go, Docker
- **Comprehensive Detection**: SQL injection, XSS, CSRF, hardcoded secrets, weak cryptography
- **Real-Time Scanning**: Live vulnerability detection with WebSocket updates
- **Pattern-Based Rules**: Customizable security rule engine

### 🏗️ CI/CD Integration
- **Jenkins Pipeline**: Complete Jenkinsfile with security gates
- **SonarQube Integration**: Code quality and security analysis
- **Kubernetes Deployment**: Production-ready K8s manifests with security policies
- **Docker Support**: Multi-stage builds with security scanning

### 🤖 Automated Remediation
- **AI-Powered Suggestions**: Intelligent fix recommendations
- **Auto-Fixing**: Safe automatic remediation for low-risk issues  
- **Custom Patterns**: Configurable remediation templates
- **Risk Assessment**: Smart evaluation of fix safety

### 📊 Dashboard & Reporting
- **Real-Time Dashboard**: Live metrics and scan results
- **Executive Reports**: High-level security posture overview
- **Compliance Reporting**: NIST, ISO 27001, PCI DSS frameworks
- **Trend Analysis**: Historical security metrics and improvements

### ☸️ Kubernetes Security
- **Cluster Scanning**: Pod security policies and misconfigurations
- **Network Policies**: Automated security policy recommendations
- **RBAC Analysis**: Permission and access control assessment
- **Container Security**: Image vulnerability scanning

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Dashboard     │    │   API Gateway   │    │  Scanner Engine │
│   (React/HTML)  │◄──►│   (Express.js)  │◄──►│   (Node.js)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   WebSocket     │    │   Database      │    │  Remediation    │
│   (Socket.IO)   │    │  (PostgreSQL)   │    │   Engine        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Integration Layer                            │
│  Jenkins • SonarQube • Kubernetes • Docker • GitHub/GitLab     │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- **Node.js** 18+ 
- **Docker** & **Docker Compose**
- **Kubernetes** cluster (optional)
- **Jenkins** (for CI/CD integration)
- **SonarQube** (for code quality analysis)

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/sandeep-rajendiran/secure-code-analyzer.git
cd secure-code-analyzer
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Start Development Server
```bash
npm run dev
```

### 5. Access Dashboard
```
http://localhost:3000
```

## 🐳 Docker Deployment

### Build and Run
```bash
# Build image
docker build -t secure-code-analyzer .

# Run container
docker run -p 3000:3000 -p 8080:8080 secure-code-analyzer
```

### Docker Compose
```bash
docker-compose up -d
```

## ☸️ Kubernetes Deployment

### Deploy to Kubernetes
```bash
# Create namespace and deploy
kubectl apply -f k8s/manifests/

# Check deployment status
kubectl get pods -n secure-code-analyzer

# Port forward to access dashboard
kubectl port-forward -n secure-code-analyzer svc/nginx-proxy-service 8080:80
```

### Access Dashboard
```
http://localhost:8080
```

## 🔧 Configuration

### Environment Variables
```bash
# Application
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=secure_code_analyzer
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# SonarQube
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=your_token

# Jenkins
JENKINS_URL=http://localhost:8080
JENKINS_TOKEN=your_token

# Security
JWT_SECRET=your_jwt_secret
ENCRYPTION_KEY=your_encryption_key
```

### Security Rules Configuration
```json
{
  "rules": {
    "sql-injection": {
      "enabled": true,
      "severity": "critical",
      "patterns": ["query.*\\$\\{.*\\}"]
    },
    "hardcoded-secrets": {
      "enabled": true,
      "severity": "critical", 
      "patterns": ["(password|secret|key)\\s*=\\s*['\"][^'\"]+['\"]"]
    }
  }
}
```

## 📊 Usage Examples

### Trigger Security Scan
```bash
curl -X POST http://localhost:3000/api/v1/analysis/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "./src", "type": "security"}'
```

### Get Security Metrics
```bash
curl http://localhost:3000/api/v1/dashboard/metrics
```

### Export Security Report
```bash
curl -X POST http://localhost:3000/api/v1/dashboard/export \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "timeRange": "30d"}'
```

## 🚀 Jenkins Integration

### Add to Jenkinsfile
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Use the provided Jenkinsfile
                    load 'jenkins/Jenkinsfile'
                }
            }
        }
    }
}
```

### Shared Library Usage
```groovy
@Library('secure-code-analyzer') _

pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                secureCodeAnalysis([
                    projectName: 'my-project',
                    threshold: 'HIGH',
                    minScore: 75
                ])
            }
        }
    }
}
```

## 🔒 Security Features

### Vulnerability Detection
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Hardcoded Secrets
- Weak Cryptography
- Insecure Transport
- Path Traversal
- Input Validation Issues

### Compliance Frameworks
- **NIST Cybersecurity Framework**
- **ISO 27001**
- **PCI DSS**
- **HIPAA** (Healthcare)
- **SOX** (Sarbanes-Oxley)

### Security Policies
- Pod Security Standards
- Network Policies
- RBAC Controls
- Container Security
- Secrets Management

## 📈 Monitoring & Metrics

### Key Metrics
- Security vulnerabilities by severity
- Code quality scores
- Test coverage percentages
- Compliance status
- Remediation rates

### Real-Time Features
- WebSocket-based live updates
- Scan progress monitoring
- Alert notifications
- Dashboard metrics

## 🛠️ Development

### Running Tests
```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# Coverage report
npm run test:coverage
```

### Linting & Code Quality
```bash
# ESLint
npm run lint
npm run lint:fix

# Security check
npm run security:check

# SonarQube analysis
npm run sonar
```

### Project Structure
```
secure-code-analyzer/
├── src/
│   ├── analyzers/           # Security analysis engines
│   ├── api/                 # REST API routes
│   ├── integrations/        # Third-party integrations
│   ├── kubernetes/          # K8s security scanning
│   ├── remediation/         # Auto-fix engine
│   └── utils/              # Utilities
├── jenkins/                # CI/CD pipeline configs
├── k8s/                    # Kubernetes manifests
├── dashboard/              # Web dashboard
├── tests/                  # Test files
└── docs/                   # Documentation
```

## 🔗 Integrations

### Supported Platforms
- **GitHub** / **GitLab** / **Bitbucket**
- **Jenkins** / **GitLab CI** / **GitHub Actions**
- **SonarQube** / **SonarCloud**
- **Kubernetes** / **OpenShift**
- **Docker Hub** / **Harbor** / **ECR**

### Notification Channels
- **Slack** webhooks
- **Microsoft Teams**
- **Email** notifications
- **Jira** ticket creation
- **Custom webhooks**

## 📚 API Documentation

### Core Endpoints
```
GET    /api/v1/health              # System health
POST   /api/v1/analysis/scan       # Start security scan
GET    /api/v1/analysis/:id        # Get scan results
GET    /api/v1/dashboard/metrics   # Security metrics
POST   /api/v1/dashboard/export    # Export reports
GET    /api/v1/reports/security    # Security report
```

### WebSocket Events
```javascript
// Connect to WebSocket
const socket = io('ws://localhost:3000');

// Listen for scan updates
socket.on('scan-update', (data) => {
    console.log('Scan progress:', data);
});

// Listen for metric updates
socket.on('metrics-update', (data) => {
    console.log('New metrics:', data);
});
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** Pull Request

### Development Guidelines
- Follow ESLint configuration
- Write comprehensive tests
- Update documentation
- Follow security best practices

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP** for security guidelines
- **NIST** for cybersecurity framework
- **Kubernetes** security community
- **Node.js** ecosystem contributors

## 📞 Support

- 📖 **Documentation**: [Wiki](https://github.com/sandeep-rajendiran/secure-code-analyzer/wiki)
- 🐛 **Issues**: [GitHub Issues](https://github.com/sandeep-rajendiran/secure-code-analyzer/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/sandeep-rajendiran/secure-code-analyzer/discussions)
- 📧 **Email**: security@yourcompany.com

## 🗺️ Roadmap

### v1.1 (Next Release)
- [ ] Machine Learning vulnerability detection
- [ ] Advanced compliance automation
- [ ] Mobile app support
- [ ] Enhanced AI remediation

### v1.2 (Future)
- [ ] Multi-cloud support (AWS, Azure, GCP)
- [ ] Advanced threat modeling
- [ ] Zero-trust architecture analysis
- [ ] Blockchain security scanning

---

**🛡️ Built with security in mind for the modern DevSecOps workflow**

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=secure-code-analyzer&metric=security_rating)](https://sonarcloud.io/dashboard?id=secure-code-analyzer)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=secure-code-analyzer&metric=alert_status)](https://sonarcloud.io/dashboard?id=secure-code-analyzer)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=secure-code-analyzer&metric=coverage)](https://sonarcloud.io/dashboard?id=secure-code-analyzer)
[![Docker Pulls](https://img.shields.io/docker/pulls/secure-code-analyzer)](https://hub.docker.com/r/secure-code-analyzer)
