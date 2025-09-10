#!/usr/bin/env groovy

/**
 * Jenkins Shared Library for Secure Code Analysis
 * Reusable security pipeline components
 */

def call(Map config) {
    pipeline {
        agent any
        
        environment {
            SCANNER_IMAGE = config.scannerImage ?: 'secure-code-analyzer:latest'
            SECURITY_THRESHOLD = config.threshold ?: 'MEDIUM'
            TARGET_PATH = config.targetPath ?: './src'
        }
        
        stages {
            stage('Security Scan Setup') {
                steps {
                    script {
                        echo "🔍 Starting security analysis for ${config.projectName}"
                        
                        // Create reports directory
                        sh 'mkdir -p reports/security'
                        
                        // Download latest security rules
                        sh '''
                            curl -o security-rules.json \
                                https://api.secure-code-analyzer.com/v1/rules/latest
                        '''
                    }
                }
            }
            
            stage('Multi-Language Security Analysis') {
                parallel {
                    stage('JavaScript/Node.js') {
                        when {
                            anyOf {
                                fileExists('package.json')
                                fileExists('yarn.lock')
                            }
                        }
                        steps {
                            analyzeJavaScript()
                        }
                    }
                    
                    stage('Python') {
                        when {
                            anyOf {
                                fileExists('requirements.txt')
                                fileExists('Pipfile')
                                fileExists('pyproject.toml')
                            }
                        }
                        steps {
                            analyzePython()
                        }
                    }
                    
                    stage('Java') {
                        when {
                            anyOf {
                                fileExists('pom.xml')
                                fileExists('build.gradle')
                            }
                        }
                        steps {
                            analyzeJava()
                        }
                    }
                    
                    stage('Docker') {
                        when {
                            fileExists('Dockerfile')
                        }
                        steps {
                            analyzeDocker()
                        }
                    }
                    
                    stage('Infrastructure as Code') {
                        when {
                            anyOf {
                                fileExists('*.tf')
                                fileExists('*.yaml')
                                fileExists('*.yml')
                            }
                        }
                        steps {
                            analyzeInfrastructure()
                        }
                    }
                }
            }
            
            stage('Consolidate Results') {
                steps {
                    script {
                        consolidateSecurityResults()
                        
                        // Generate security score
                        def securityScore = calculateSecurityScore()
                        env.SECURITY_SCORE = securityScore.toString()
                        
                        echo "🛡️ Security Score: ${securityScore}/100"
                        
                        // Fail if below threshold
                        if (securityScore < (config.minScore ?: 70)) {
                            error "Security score ${securityScore} below minimum threshold ${config.minScore ?: 70}"
                        }
                    }
                }
            }
        }
        
        post {
            always {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports/security',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Analysis Report'
                ])
                
                archiveArtifacts artifacts: 'reports/security/**/*', allowEmptyArchive: true
            }
        }
    }
}

def analyzeJavaScript() {
    sh '''
        echo "🔍 Analyzing JavaScript/Node.js code..."
        
        # ESLint Security Plugin
        npx eslint ${TARGET_PATH} --ext .js,.ts \
            --config .eslintrc.security.json \
            --format json --output-file reports/security/eslint-security.json || true
        
        # Semgrep for JavaScript
        docker run --rm -v $(pwd):/src returntocorp/semgrep:latest \
            --config=p/javascript --config=p/nodejs \
            --json --output=/src/reports/security/semgrep-js.json /src || true
        
        # NodeJsScan
        docker run --rm -v $(pwd):/app opensecurity/nodejsscan:latest \
            --json --output /app/reports/security/nodejsscan.json /app || true
        
        # Custom security patterns
        node scripts/js-security-analyzer.js
    '''
}

def analyzePython() {
    sh '''
        echo "🔍 Analyzing Python code..."
        
        # Bandit
        bandit -r ${TARGET_PATH} -f json -o reports/security/bandit.json || true
        
        # Safety (dependency vulnerabilities)
        safety check --json --output reports/security/safety.json || true
        
        # Semgrep for Python
        docker run --rm -v $(pwd):/src returntocorp/semgrep:latest \
            --config=p/python --config=p/django --config=p/flask \
            --json --output=/src/reports/security/semgrep-py.json /src || true
        
        # Custom security patterns
        python scripts/py-security-analyzer.py
    '''
}

def analyzeJava() {
    sh '''
        echo "🔍 Analyzing Java code..."
        
        # SpotBugs with FindSecBugs
        spotbugs -textui -effort:max -low -xml:withMessages \
            -output reports/security/spotbugs.xml \
            -pluginList findsecbugs-plugin.jar target/classes || true
        
        # PMD Security Rules
        pmd -d ${TARGET_PATH} -R category/java/security.xml \
            -f xml -r reports/security/pmd-security.xml || true
        
        # Semgrep for Java
        docker run --rm -v $(pwd):/src returntocorp/semgrep:latest \
            --config=p/java --config=p/spring \
            --json --output=/src/reports/security/semgrep-java.json /src || true
    '''
}

def analyzeDocker() {
    sh '''
        echo "🔍 Analyzing Docker configuration..."
        
        # Hadolint
        docker run --rm -i hadolint/hadolint:latest \
            --format json < Dockerfile > reports/security/hadolint.json || true
        
        # Dockerfile security scan
        docker run --rm -v $(pwd):/project \
            securecodewarrior/docker-security-scanner:latest \
            /project/Dockerfile > reports/security/dockerfile-scan.json || true
        
        # Custom Dockerfile analyzer
        node scripts/dockerfile-analyzer.js
    '''
}

def analyzeInfrastructure() {
    sh '''
        echo "🔍 Analyzing Infrastructure as Code..."
        
        # Checkov
        checkov -d . --framework terraform --framework cloudformation --framework kubernetes \
            --output json --output-file reports/security/checkov.json || true
        
        # tfsec for Terraform
        tfsec . --format json --out reports/security/tfsec.json || true
        
        # kube-score for Kubernetes
        find . -name "*.yaml" -o -name "*.yml" | xargs -I {} \
            kube-score score {} --output-format json > reports/security/kube-score.json || true
        
        # Custom IaC analyzer
        python scripts/iac-analyzer.py
    '''
}

def consolidateSecurityResults() {
    sh '''
        echo "📊 Consolidating security results..."
        
        # Run consolidation script
        node scripts/consolidate-security-results.js
        
        # Generate HTML report
        node scripts/generate-security-report.js
        
        # Calculate metrics
        node scripts/calculate-security-metrics.js
    '''
}

def calculateSecurityScore() {
    def result = sh(
        script: 'node scripts/calculate-security-score.js',
        returnStdout: true
    ).trim()
    
    return result.toInteger()
}

// Additional utility functions
def notifySecurityTeam(severity, message) {
    if (severity in ['CRITICAL', 'HIGH']) {
        emailext (
            subject: "[SECURITY ALERT] ${severity} - ${env.JOB_NAME}",
            body: message,
            to: "${env.SECURITY_TEAM_EMAIL}"
        )
    }
}

def createSecurityTicket(issue) {
    sh """
        curl -X POST "${env.JIRA_API_URL}/issue" \
            -H "Authorization: Basic ${env.JIRA_TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{
                "fields": {
                    "project": {"key": "SEC"},
                    "summary": "Security Issue: ${issue.title}",
                    "description": "${issue.description}",
                    "priority": {"name": "${issue.severity}"},
                    "labels": ["security", "automated"]
                }
            }'
    """
}

def updateSecurityDashboard() {
    sh '''
        curl -X POST "${SECURITY_DASHBOARD_WEBHOOK}" \
            -H "Content-Type: application/json" \
            -d "{
                \\"project\\": \\"${JOB_NAME}\\",
                \\"build\\": \\"${BUILD_NUMBER}\\",
                \\"score\\": \\"${SECURITY_SCORE}\\",
                \\"timestamp\\": \\"$(date -Iseconds)\\",
                \\"branch\\": \\"${BRANCH_NAME}\\"
            }"
    '''
}