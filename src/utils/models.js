class SecurityRule {
  constructor(id, name, pattern, severity, category, description) {
    this.id = id;
    this.name = name;
    this.pattern = pattern;
    this.severity = severity; // critical, high, medium, low
    this.category = category;
    this.description = description;
    this.enabled = true;
  }
}

class Vulnerability {
  constructor(ruleId, filePath, line, column, message, severity, category) {
    this.id = `${ruleId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    this.ruleId = ruleId;
    this.filePath = filePath;
    this.line = line || 0;
    this.column = column || 0;
    this.message = message;
    this.severity = severity;
    this.category = category;
    this.timestamp = new Date().toISOString();
    this.status = 'open'; // open, fixed, false_positive, accepted_risk
  }
}

class AnalysisResult {
  constructor(scanId, targetPath, scanType = 'full') {
    this.scanId = scanId;
    this.targetPath = targetPath;
    this.scanType = scanType;
    this.startTime = new Date().toISOString();
    this.endTime = null;
    this.status = 'running'; // running, completed, failed
    this.vulnerabilities = [];
    this.summary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    this.metrics = {
      filesScanned: 0,
      linesAnalyzed: 0,
      executionTime: 0,
      coverage: 0
    };
  }

  addVulnerability(vulnerability) {
    this.vulnerabilities.push(vulnerability);
    this.updateSummary();
  }

  updateSummary() {
    this.summary = this.vulnerabilities.reduce((acc, vuln) => {
      acc.total++;
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  }

  complete() {
    this.endTime = new Date().toISOString();
    this.status = 'completed';
    this.metrics.executionTime = Date.parse(this.endTime) - Date.parse(this.startTime);
  }

  fail(error) {
    this.endTime = new Date().toISOString();
    this.status = 'failed';
    this.error = error;
  }
}

class ScanConfiguration {
  constructor(options = {}) {
    this.includePatterns = options.includePatterns || ['**/*.js', '**/*.ts', '**/*.py', '**/*.java'];
    this.excludePatterns = options.excludePatterns || ['node_modules/**', '**/test/**', '**/tests/**'];
    this.rulesets = options.rulesets || ['security', 'quality'];
    this.severity = options.severity || 'medium'; // minimum severity to report
    this.maxFileSize = options.maxFileSize || 1024 * 1024; // 1MB
    this.timeout = options.timeout || 300000; // 5 minutes
    this.parallel = options.parallel || true;
    this.outputFormat = options.outputFormat || 'json';
  }
}

module.exports = {
  SecurityRule,
  Vulnerability,
  AnalysisResult,
  ScanConfiguration
};