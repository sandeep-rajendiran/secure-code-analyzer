#!/usr/bin/env groovy

/**
 * Security Gate Implementation
 * Quality gates for security findings and compliance
 */

@Library('secure-code-analyzer') _

def call(Map config) {
    def securityResults = [:]
    def gatesPassed = []
    def gatesFailed = []
    
    stage('Security Gate Analysis') {
        script {
            echo "🔒 Evaluating security gates..."
            
            // Load security results
            securityResults = loadSecurityResults()
            
            // Define security gates
            def gates = [
                [
                    name: 'Critical Vulnerabilities',
                    condition: { results -> results.critical <= (config.maxCritical ?: 0) },
                    message: "Critical vulnerabilities found: ${securityResults.critical}"
                ],
                [
                    name: 'High Severity Issues',
                    condition: { results -> results.high <= (config.maxHigh ?: 2) },
                    message: "High severity issues found: ${securityResults.high}"
                ],
                [
                    name: 'Security Score',
                    condition: { results -> results.score >= (config.minScore ?: 75) },
                    message: "Security score too low: ${securityResults.score}/100"
                ],
                [
                    name: 'Dependency Vulnerabilities',
                    condition: { results -> results.dependencies.critical == 0 },
                    message: "Critical dependency vulnerabilities found: ${securityResults.dependencies.critical}"
                ],
                [
                    name: 'Secrets Detection',
                    condition: { results -> results.secrets.count == 0 },
                    message: "Secrets detected in code: ${securityResults.secrets.count}"
                ],
                [
                    name: 'License Compliance',
                    condition: { results -> results.licenses.violations == 0 },
                    message: "License compliance violations: ${securityResults.licenses.violations}"
                ],
                [
                    name: 'Container Security',
                    condition: { results -> results.container.critical <= 0 },
                    message: "Critical container vulnerabilities: ${securityResults.container.critical}"
                ],
                [
                    name: 'Infrastructure Security',
                    condition: { results -> results.infrastructure.high <= 1 },
                    message: "Infrastructure security issues: ${securityResults.infrastructure.high}"
                ]
            ]
            
            // Evaluate each gate
            gates.each { gate ->
                try {
                    if (gate.condition(securityResults)) {
                        gatesPassed << gate.name
                        echo "✅ ${gate.name}: PASSED"
                    } else {
                        gatesFailed << gate.name
                        echo "❌ ${gate.name}: FAILED - ${gate.message}"
                        
                        // Create security incident for critical failures
                        if (gate.name in ['Critical Vulnerabilities', 'Secrets Detection']) {
                            createSecurityIncident(gate.name, gate.message)
                        }
                    }
                } catch (Exception e) {
                    echo "⚠️ ${gate.name}: ERROR - ${e.message}"
                    gatesFailed << gate.name
                }
            }
            
            // Summary
            echo """
🛡️ Security Gate Summary:
   Passed: ${gatesPassed.size()}/${gates.size()}
   Failed: ${gatesFailed.size()}/${gates.size()}
   
✅ Passed Gates:
${gatesPassed.collect { "   - ${it}" }.join('\n')}

${gatesFailed.size() > 0 ? "❌ Failed Gates:\n${gatesFailed.collect { "   - ${it}" }.join('\n')}" : ""}
            """
            
            // Store results
            env.SECURITY_GATES_PASSED = gatesPassed.size().toString()
            env.SECURITY_GATES_FAILED = gatesFailed.size().toString()
            env.SECURITY_GATES_TOTAL = gates.size().toString()
            
            // Generate security gate report
            generateSecurityGateReport(gates, securityResults)
            
            // Determine if build should fail
            if (gatesFailed.size() > 0) {
                if (config.failOnGateFailure != false) {
                    if (params.FORCE_DEPLOY == true) {
                        echo "⚠️ Security gates failed but deployment forced by user"
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        error "Security gates failed: ${gatesFailed.join(', ')}"
                    }
                } else {
                    echo "⚠️ Security gates failed but build continuing due to configuration"
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }
    }
    
    return [
        passed: gatesPassed,
        failed: gatesFailed,
        results: securityResults
    ]
}

def loadSecurityResults() {
    def results = [:]
    
    try {
        // Load consolidated security report
        if (fileExists('reports/security/consolidated-results.json')) {
            def jsonContent = readFile('reports/security/consolidated-results.json')
            results = readJSON text: jsonContent
        } else {
            // Fallback: aggregate individual reports
            results = aggregateSecurityResults()
        }
        
        // Ensure all required fields exist
        results.critical = results.critical ?: 0
        results.high = results.high ?: 0
        results.medium = results.medium ?: 0
        results.low = results.low ?: 0
        results.score = results.score ?: 0
        results.dependencies = results.dependencies ?: [critical: 0, high: 0, medium: 0, low: 0]
        results.secrets = results.secrets ?: [count: 0, types: []]
        results.licenses = results.licenses ?: [violations: 0, issues: []]
        results.container = results.container ?: [critical: 0, high: 0, medium: 0, low: 0]
        results.infrastructure = results.infrastructure ?: [critical: 0, high: 0, medium: 0, low: 0]
        
    } catch (Exception e) {
        echo "Warning: Failed to load security results: ${e.message}"
        // Return default empty results
        results = [
            critical: 999,
            high: 999,
            medium: 0,
            low: 0,
            score: 0,
            dependencies: [critical: 999, high: 0, medium: 0, low: 0],
            secrets: [count: 999, types: []],
            licenses: [violations: 0, issues: []],
            container: [critical: 999, high: 0, medium: 0, low: 0],
            infrastructure: [critical: 0, high: 999, medium: 0, low: 0]
        ]
    }
    
    return results
}

def aggregateSecurityResults() {
    def results = [
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        score: 100,
        dependencies: [critical: 0, high: 0, medium: 0, low: 0],
        secrets: [count: 0, types: []],
        licenses: [violations: 0, issues: []],
        container: [critical: 0, high: 0, medium: 0, low: 0],
        infrastructure: [critical: 0, high: 0, medium: 0, low: 0]
    ]
    
    // Aggregate from individual tool reports
    def reportFiles = [
        'reports/security/eslint-security.json',
        'reports/security/semgrep-js.json',
        'reports/security/bandit.json',
        'reports/security/safety.json',
        'reports/security/spotbugs.xml',
        'reports/security/trivy-scan.json',
        'reports/security/checkov.json'
    ]
    
    reportFiles.each { reportFile ->
        if (fileExists(reportFile)) {
            try {
                parseSecurityReport(reportFile, results)
            } catch (Exception e) {
                echo "Warning: Failed to parse ${reportFile}: ${e.message}"
            }
        }
    }
    
    // Calculate overall security score
    results.score = calculateOverallScore(results)
    
    return results
}

def parseSecurityReport(reportFile, results) {
    def content = readFile(reportFile)
    
    if (reportFile.endsWith('.json')) {
        def json = readJSON text: content
        
        // Parse different tool formats
        if (reportFile.contains('eslint')) {
            parseESLintReport(json, results)
        } else if (reportFile.contains('semgrep')) {
            parseSemgrepReport(json, results)
        } else if (reportFile.contains('bandit')) {
            parseBanditReport(json, results)
        } else if (reportFile.contains('safety')) {
            parseSafetyReport(json, results)
        } else if (reportFile.contains('trivy')) {
            parseTrivyReport(json, results)
        } else if (reportFile.contains('checkov')) {
            parseCheckovReport(json, results)
        }
    }
}

def parseESLintReport(json, results) {
    json.each { file ->
        file.messages?.each { message ->
            if (message.ruleId?.startsWith('security/')) {
                def severity = message.severity == 2 ? 'high' : 'medium'
                results[severity]++
            }
        }
    }
}

def parseSemgrepReport(json, results) {
    json.results?.each { finding ->
        def severity = finding.extra?.severity?.toLowerCase() ?: 'medium'
        if (severity in ['critical', 'high', 'medium', 'low']) {
            results[severity]++
        }
    }
}

def parseBanditReport(json, results) {
    json.results?.each { finding ->
        def severity = finding.issue_severity?.toLowerCase()
        if (severity in ['critical', 'high', 'medium', 'low']) {
            results[severity]++
        }
    }
}

def parseSafetyReport(json, results) {
    json.each { vuln ->
        def severity = vuln.vulnerability_id ? 'high' : 'medium'
        results.dependencies[severity]++
    }
}

def parseTrivyReport(json, results) {
    json.Results?.each { result ->
        result.Vulnerabilities?.each { vuln ->
            def severity = vuln.Severity?.toLowerCase()
            if (severity in ['critical', 'high', 'medium', 'low']) {
                results.container[severity]++
            }
        }
    }
}

def parseCheckovReport(json, results) {
    json.results?.failed_checks?.each { check ->
        def severity = check.severity?.toLowerCase() ?: 'medium'
        if (severity in ['critical', 'high', 'medium', 'low']) {
            results.infrastructure[severity]++
        }
    }
}

def calculateOverallScore(results) {
    def score = 100
    
    // Deduct points for vulnerabilities
    score -= (results.critical * 20)
    score -= (results.high * 10)
    score -= (results.medium * 3)
    score -= (results.low * 1)
    
    // Deduct points for dependency issues
    score -= (results.dependencies.critical * 15)
    score -= (results.dependencies.high * 5)
    
    // Deduct points for secrets
    score -= (results.secrets.count * 25)
    
    // Deduct points for container issues
    score -= (results.container.critical * 15)
    score -= (results.container.high * 5)
    
    // Deduct points for infrastructure issues
    score -= (results.infrastructure.critical * 10)
    score -= (results.infrastructure.high * 3)
    
    return Math.max(0, score)
}

def generateSecurityGateReport(gates, results) {
    def html = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Gate Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .gate { margin: 10px 0; padding: 15px; border-radius: 5px; }
        .passed { background: #d5f4e6; border-left: 5px solid #27ae60; }
        .failed { background: #fadbd8; border-left: 5px solid #e74c3c; }
        .metrics { display: flex; justify-content: space-around; margin: 20px 0; }
        .metric { text-align: center; padding: 10px; background: #ecf0f1; border-radius: 5px; }
        .score { font-size: 2em; font-weight: bold; color: #2c3e50; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Gate Report</h1>
        <p>Build: ${env.BUILD_NUMBER} | Branch: ${env.BRANCH_NAME} | Date: ${new Date()}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <div class="score">${results.score}</div>
            <div>Security Score</div>
        </div>
        <div class="metric">
            <div class="score">${env.SECURITY_GATES_PASSED}</div>
            <div>Gates Passed</div>
        </div>
        <div class="metric">
            <div class="score">${env.SECURITY_GATES_FAILED}</div>
            <div>Gates Failed</div>
        </div>
    </div>
    
    <h2>Gate Results</h2>
"""
    
    gates.each { gate ->
        def status = gate.condition(results) ? 'passed' : 'failed'
        def icon = status == 'passed' ? '✅' : '❌'
        html += """
    <div class="gate ${status}">
        <h3>${icon} ${gate.name}</h3>
        <p>${gate.message}</p>
    </div>
"""
    }
    
    html += """
    <h2>Detailed Findings</h2>
    <table border="1" style="width: 100%; border-collapse: collapse;">
        <tr>
            <th>Category</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
        <tr>
            <td>Code Issues</td>
            <td>${results.critical}</td>
            <td>${results.high}</td>
            <td>${results.medium}</td>
            <td>${results.low}</td>
        </tr>
        <tr>
            <td>Dependencies</td>
            <td>${results.dependencies.critical}</td>
            <td>${results.dependencies.high}</td>
            <td>${results.dependencies.medium}</td>
            <td>${results.dependencies.low}</td>
        </tr>
        <tr>
            <td>Container</td>
            <td>${results.container.critical}</td>
            <td>${results.container.high}</td>
            <td>${results.container.medium}</td>
            <td>${results.container.low}</td>
        </tr>
        <tr>
            <td>Infrastructure</td>
            <td>${results.infrastructure.critical}</td>
            <td>${results.infrastructure.high}</td>
            <td>${results.infrastructure.medium}</td>
            <td>${results.infrastructure.low}</td>
        </tr>
    </table>
</body>
</html>
"""
    
    writeFile file: 'reports/security/security-gate-report.html', text: html
}

def createSecurityIncident(gateName, message) {
    sh """
        curl -X POST "${env.SECURITY_INCIDENT_WEBHOOK}" \
            -H "Content-Type: application/json" \
            -d '{
                "title": "Security Gate Failure: ${gateName}",
                "description": "${message}",
                "severity": "high",
                "project": "${env.JOB_NAME}",
                "build": "${env.BUILD_NUMBER}",
                "branch": "${env.BRANCH_NAME}",
                "timestamp": "${new Date().format('yyyy-MM-dd HH:mm:ss')}"
            }' || echo "Failed to create security incident"
    """
}