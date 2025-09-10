const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const logger = require('../utils/logger');
const config = require('../utils/config');

class SonarQubeIntegration {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || config.sonarqube.url || 'http://localhost:9000';
    this.token = options.token || config.sonarqube.token;
    this.projectKey = options.projectKey || 'secure-code-analyzer';
    this.organization = options.organization || config.sonarqube.organization;
    this.qualityGate = options.qualityGate || config.sonarqube.qualityGate || 'Sonar way';
    
    this.client = axios.create({
      baseURL: this.baseUrl,
      auth: {
        username: this.token,
        password: ''
      },
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    this.initialized = false;
    this.metrics = new Map();
    this.qualityGateStatus = null;
  }

  async initialize() {
    try {
      logger.info('Initializing SonarQube integration...');
      
      // Test connection
      await this.testConnection();
      
      // Setup project if needed
      await this.setupProject();
      
      // Configure quality gate
      await this.configureQualityGate();
      
      this.initialized = true;
      logger.info('✅ SonarQube integration initialized successfully');
      
      return true;
    } catch (error) {
      logger.error('❌ Failed to initialize SonarQube integration:', error.message);
      throw error;
    }
  }

  async testConnection() {
    try {
      const response = await this.client.get('/api/system/status');
      
      if (response.data.status !== 'UP') {
        throw new Error(`SonarQube server not ready: ${response.data.status}`);
      }
      
      logger.info('✅ SonarQube connection test successful');
      return true;
    } catch (error) {
      logger.error('❌ SonarQube connection test failed:', error.message);
      throw error;
    }
  }

  async setupProject() {
    try {
      // Check if project exists
      const existingProject = await this.getProject();
      
      if (!existingProject) {
        logger.info(`Creating SonarQube project: ${this.projectKey}`);
        
        const params = {
          name: 'Secure Code Analyzer',
          project: this.projectKey,
          visibility: 'private'
        };
        
        if (this.organization) {
          params.organization = this.organization;
        }
        
        await this.client.post('/api/projects/create', null, { params });
        logger.info('✅ Project created successfully');
      } else {
        logger.info('✅ Project already exists');
      }
      
      // Set project settings
      await this.configureProjectSettings();
      
    } catch (error) {
      logger.error('❌ Failed to setup project:', error.message);
      throw error;
    }
  }

  async getProject() {
    try {
      const params = { projects: this.projectKey };
      if (this.organization) {
        params.organization = this.organization;
      }
      
      const response = await this.client.get('/api/projects/search', { params });
      
      return response.data.components.find(project => project.key === this.projectKey);
    } catch (error) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  async configureProjectSettings() {
    const settings = [
      {
        key: 'sonar.javascript.lcov.reportPaths',
        value: 'coverage/lcov.info'
      },
      {
        key: 'sonar.testExecutionReportPaths',
        value: 'coverage/test-reporter.xml'
      },
      {
        key: 'sonar.sources',
        value: 'src'
      },
      {
        key: 'sonar.tests',
        value: 'tests'
      },
      {
        key: 'sonar.exclusions',
        value: '**/node_modules/**,**/vendor/**,**/dist/**,**/build/**'
      },
      {
        key: 'sonar.test.exclusions',
        value: '**/*.test.js,**/*.spec.js'
      },
      {
        key: 'sonar.coverage.exclusions',
        value: '**/*.test.js,**/*.spec.js,**/node_modules/**'
      }
    ];

    for (const setting of settings) {
      try {
        await this.client.post('/api/settings/set', null, {
          params: {
            component: this.projectKey,
            key: setting.key,
            value: setting.value
          }
        });
      } catch (error) {
        logger.warn(`Failed to set setting ${setting.key}:`, error.message);
      }
    }
  }

  async configureQualityGate() {
    try {
      // Get available quality gates
      const gates = await this.getQualityGates();
      const targetGate = gates.find(gate => 
        gate.name === this.qualityGate || gate.isDefault
      );
      
      if (targetGate) {
        // Associate project with quality gate
        await this.client.post('/api/qualitygates/select', null, {
          params: {
            projectKey: this.projectKey,
            gateId: targetGate.id
          }
        });
        
        logger.info(`✅ Quality gate "${targetGate.name}" configured for project`);
      }
    } catch (error) {
      logger.warn('Failed to configure quality gate:', error.message);
    }
  }

  async getQualityGates() {
    try {
      const response = await this.client.get('/api/qualitygates/list');
      return response.data.qualitygates || [];
    } catch (error) {
      logger.error('Failed to fetch quality gates:', error.message);
      return [];
    }
  }

  async runAnalysis(options = {}) {
    try {
      logger.info('🔍 Starting SonarQube analysis...');
      
      const analysisOptions = {
        projectPath: options.projectPath || process.cwd(),
        branch: options.branch || 'main',
        pullRequest: options.pullRequest,
        sonarScannerPath: options.sonarScannerPath || 'sonar-scanner',
        additionalProperties: options.additionalProperties || {}
      };
      
      // Prepare analysis properties
      const properties = this.buildAnalysisProperties(analysisOptions);
      
      // Execute analysis
      const result = await this.executeSonarScanner(properties, analysisOptions);
      
      // Wait for analysis completion
      const taskResult = await this.waitForAnalysisCompletion(result.taskId);
      
      // Fetch results
      const analysisResults = await this.fetchAnalysisResults();
      
      logger.info('✅ SonarQube analysis completed successfully');
      
      return {
        taskId: result.taskId,
        status: taskResult.status,
        results: analysisResults,
        qualityGate: this.qualityGateStatus,
        dashboardUrl: `${this.baseUrl}/dashboard?id=${this.projectKey}`
      };
      
    } catch (error) {
      logger.error('❌ SonarQube analysis failed:', error.message);
      throw error;
    }
  }

  buildAnalysisProperties(options) {
    const properties = {
      'sonar.projectKey': this.projectKey,
      'sonar.projectName': 'Secure Code Analyzer',
      'sonar.projectVersion': process.env.BUILD_NUMBER || '1.0.0',
      'sonar.sources': 'src',
      'sonar.tests': 'tests',
      'sonar.sourceEncoding': 'UTF-8',
      'sonar.javascript.lcov.reportPaths': 'coverage/lcov.info',
      'sonar.testExecutionReportPaths': 'coverage/test-reporter.xml',
      'sonar.exclusions': '**/node_modules/**,**/vendor/**,**/dist/**,**/build/**',
      'sonar.test.exclusions': '**/*.test.js,**/*.spec.js',
      'sonar.coverage.exclusions': '**/*.test.js,**/*.spec.js,**/node_modules/**',
      'sonar.qualitygate.wait': 'true',
      'sonar.qualitygate.timeout': '300'
    };

    // Add host URL if configured
    if (this.baseUrl !== 'http://localhost:9000') {
      properties['sonar.host.url'] = this.baseUrl;
    }

    // Add authentication token
    if (this.token) {
      properties['sonar.login'] = this.token;
    }

    // Add organization if configured
    if (this.organization) {
      properties['sonar.organization'] = this.organization;
    }

    // Add branch information
    if (options.branch && options.branch !== 'main') {
      properties['sonar.branch.name'] = options.branch;
      properties['sonar.branch.target'] = 'main';
    }

    // Add pull request information
    if (options.pullRequest) {
      properties['sonar.pullrequest.key'] = options.pullRequest.key;
      properties['sonar.pullrequest.branch'] = options.pullRequest.branch;
      properties['sonar.pullrequest.base'] = options.pullRequest.base || 'main';
      
      if (options.pullRequest.provider) {
        properties['sonar.pullrequest.provider'] = options.pullRequest.provider;
      }
    }

    // Add additional properties
    Object.assign(properties, options.additionalProperties);

    return properties;
  }

  async executeSonarScanner(properties, options) {
    const { spawn } = require('child_process');
    const propertiesFile = path.join(options.projectPath, 'sonar-project.properties');
    
    // Write properties to file
    const propertiesContent = Object.entries(properties)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
    
    await fs.writeFile(propertiesFile, propertiesContent);
    
    return new Promise((resolve, reject) => {
      const args = ['-Dproject.settings=' + propertiesFile];
      const scanner = spawn(options.sonarScannerPath, args, {
        cwd: options.projectPath,
        stdio: 'pipe'
      });
      
      let output = '';
      let taskId = null;
      
      scanner.stdout.on('data', (data) => {
        const line = data.toString();
        output += line;
        
        // Extract task ID
        const taskMatch = line.match(/INFO: More about the report processing at (.*)\/api\/ce\/task\?id=([^\s]+)/);
        if (taskMatch) {
          taskId = taskMatch[2];
        }
        
        logger.info(`SonarScanner: ${line.trim()}`);
      });
      
      scanner.stderr.on('data', (data) => {
        logger.warn(`SonarScanner: ${data.toString().trim()}`);
      });
      
      scanner.on('close', (code) => {
        if (code === 0) {
          resolve({ taskId, output });
        } else {
          reject(new Error(`SonarScanner exited with code ${code}`));
        }
      });
      
      scanner.on('error', (error) => {
        reject(new Error(`Failed to start SonarScanner: ${error.message}`));
      });
    });
  }

  async waitForAnalysisCompletion(taskId, timeout = 300000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        const response = await this.client.get('/api/ce/task', {
          params: { id: taskId }
        });
        
        const task = response.data.task;
        
        if (task.status === 'SUCCESS') {
          logger.info('✅ Analysis completed successfully');
          return { status: 'SUCCESS', task };
        } else if (task.status === 'FAILED' || task.status === 'CANCELED') {
          throw new Error(`Analysis failed: ${task.status} - ${task.errorMessage || 'Unknown error'}`);
        }
        
        logger.info(`📊 Analysis in progress... Status: ${task.status}`);
        await new Promise(resolve => setTimeout(resolve, 5000));
        
      } catch (error) {
        if (error.response?.status === 404) {
          logger.warn('Task not found, waiting...');
          await new Promise(resolve => setTimeout(resolve, 5000));
          continue;
        }
        throw error;
      }
    }
    
    throw new Error('Analysis timeout exceeded');
  }

  async fetchAnalysisResults() {
    try {
      // Fetch project measures
      const measures = await this.getProjectMeasures();
      this.metrics = new Map(measures.map(m => [m.metric, m.value]));
      
      // Fetch quality gate status
      this.qualityGateStatus = await this.getQualityGateStatus();
      
      // Fetch issues
      const issues = await this.getProjectIssues();
      
      return {
        metrics: Object.fromEntries(this.metrics),
        qualityGate: this.qualityGateStatus,
        issues: issues,
        summary: this.generateSummary(measures, issues)
      };
      
    } catch (error) {
      logger.error('Failed to fetch analysis results:', error.message);
      throw error;
    }
  }

  async getProjectMeasures() {
    try {
      const response = await this.client.get('/api/measures/component', {
        params: {
          component: this.projectKey,
          metricKeys: [
            'lines',
            'ncloc',
            'functions',
            'classes',
            'files',
            'coverage',
            'line_coverage',
            'branch_coverage',
            'tests',
            'test_success',
            'duplicated_lines_density',
            'complexity',
            'cognitive_complexity',
            'violations',
            'bugs',
            'vulnerabilities',
            'security_hotspots',
            'code_smells',
            'maintainability_rating',
            'reliability_rating',
            'security_rating',
            'sqale_rating'
          ].join(',')
        }
      });
      
      return response.data.component.measures || [];
    } catch (error) {
      logger.error('Failed to fetch project measures:', error.message);
      return [];
    }
  }

  async getQualityGateStatus() {
    try {
      const response = await this.client.get('/api/qualitygates/project_status', {
        params: { projectKey: this.projectKey }
      });
      
      return response.data.projectStatus;
    } catch (error) {
      logger.error('Failed to fetch quality gate status:', error.message);
      return null;
    }
  }

  async getProjectIssues(options = {}) {
    try {
      const params = {
        componentKeys: this.projectKey,
        ps: options.pageSize || 500,
        facets: 'severities,types,rules',
        additionalFields: 'rules'
      };
      
      if (options.severities) {
        params.severities = options.severities.join(',');
      }
      
      if (options.types) {
        params.types = options.types.join(',');
      }
      
      const response = await this.client.get('/api/issues/search', { params });
      
      return {
        total: response.data.total,
        issues: response.data.issues || [],
        facets: response.data.facets || []
      };
    } catch (error) {
      logger.error('Failed to fetch project issues:', error.message);
      return { total: 0, issues: [], facets: [] };
    }
  }

  generateSummary(measures, issues) {
    const metricsMap = new Map(measures.map(m => [m.metric, m.value]));
    
    return {
      codeMetrics: {
        lines: parseInt(metricsMap.get('lines')) || 0,
        nonCommentLines: parseInt(metricsMap.get('ncloc')) || 0,
        functions: parseInt(metricsMap.get('functions')) || 0,
        files: parseInt(metricsMap.get('files')) || 0,
        complexity: parseInt(metricsMap.get('complexity')) || 0
      },
      testMetrics: {
        coverage: parseFloat(metricsMap.get('coverage')) || 0,
        lineCoverage: parseFloat(metricsMap.get('line_coverage')) || 0,
        branchCoverage: parseFloat(metricsMap.get('branch_coverage')) || 0,
        tests: parseInt(metricsMap.get('tests')) || 0
      },
      qualityMetrics: {
        bugs: parseInt(metricsMap.get('bugs')) || 0,
        vulnerabilities: parseInt(metricsMap.get('vulnerabilities')) || 0,
        securityHotspots: parseInt(metricsMap.get('security_hotspots')) || 0,
        codeSmells: parseInt(metricsMap.get('code_smells')) || 0,
        duplicatedLinesDensity: parseFloat(metricsMap.get('duplicated_lines_density')) || 0
      },
      ratings: {
        maintainability: metricsMap.get('maintainability_rating') || 'A',
        reliability: metricsMap.get('reliability_rating') || 'A',
        security: metricsMap.get('security_rating') || 'A'
      },
      issues: {
        total: issues.total,
        breakdown: this.categorizeIssues(issues.issues)
      }
    };
  }

  categorizeIssues(issues) {
    const breakdown = {
      byType: { BUG: 0, VULNERABILITY: 0, CODE_SMELL: 0, SECURITY_HOTSPOT: 0 },
      bySeverity: { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 }
    };
    
    issues.forEach(issue => {
      breakdown.byType[issue.type] = (breakdown.byType[issue.type] || 0) + 1;
      breakdown.bySeverity[issue.severity] = (breakdown.bySeverity[issue.severity] || 0) + 1;
    });
    
    return breakdown;
  }

  async generateReport(analysisResults, outputPath) {
    try {
      const report = this.buildHTMLReport(analysisResults);
      await fs.writeFile(outputPath, report);
      logger.info(`✅ SonarQube report generated: ${outputPath}`);
      return outputPath;
    } catch (error) {
      logger.error('Failed to generate report:', error.message);
      throw error;
    }
  }

  buildHTMLReport(results) {
    const { summary, qualityGate, metrics } = results;
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>SonarQube Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: #4C9AFF; color: white; border-radius: 5px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #4C9AFF; }
        .metric-title { font-size: 14px; color: #666; margin-bottom: 5px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #333; }
        .quality-gate { padding: 15px; border-radius: 5px; margin: 20px 0; text-align: center; }
        .gate-passed { background: #d1f2eb; color: #155724; border: 1px solid #b8daff; }
        .gate-failed { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .issues-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .issues-table th, .issues-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .issues-table th { background: #f8f9fa; font-weight: bold; }
        .rating { display: inline-block; padding: 4px 8px; border-radius: 3px; color: white; font-weight: bold; }
        .rating-A { background: #00aa00; } .rating-B { background: #80cc00; } .rating-C { background: #ffaa00; }
        .rating-D { background: #ff8800; } .rating-E { background: #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SonarQube Analysis Report</h1>
            <p>Secure Code Analyzer - Enterprise DevSecOps</p>
            <p>Analysis Date: ${new Date().toISOString()}</p>
        </div>

        <div class="quality-gate ${qualityGate?.status === 'OK' ? 'gate-passed' : 'gate-failed'}">
            <h2>${qualityGate?.status === 'OK' ? '✅' : '❌'} Quality Gate: ${qualityGate?.status || 'Unknown'}</h2>
            ${qualityGate?.conditions ? qualityGate.conditions.map(c => 
                `<p>${c.metricKey}: ${c.actualValue} (${c.status})</p>`
            ).join('') : ''}
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-title">Lines of Code</div>
                <div class="metric-value">${summary.codeMetrics.nonCommentLines.toLocaleString()}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Test Coverage</div>
                <div class="metric-value">${summary.testMetrics.coverage.toFixed(1)}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Bugs</div>
                <div class="metric-value" style="color: #ff0000;">${summary.qualityMetrics.bugs}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Vulnerabilities</div>
                <div class="metric-value" style="color: #ff8800;">${summary.qualityMetrics.vulnerabilities}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Security Hotspots</div>
                <div class="metric-value" style="color: #ffaa00;">${summary.qualityMetrics.securityHotspots}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Code Smells</div>
                <div class="metric-value" style="color: #80cc00;">${summary.qualityMetrics.codeSmells}</div>
            </div>
        </div>

        <h3>📊 Quality Ratings</h3>
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-title">Maintainability</div>
                <div class="rating rating-${summary.ratings.maintainability}">${summary.ratings.maintainability}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Reliability</div>
                <div class="rating rating-${summary.ratings.reliability}">${summary.ratings.reliability}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Security</div>
                <div class="rating rating-${summary.ratings.security}">${summary.ratings.security}</div>
            </div>
        </div>

        <h3>🐛 Issues Breakdown</h3>
        <table class="issues-table">
            <thead>
                <tr><th>Type</th><th>Count</th></tr>
            </thead>
            <tbody>
                <tr><td>Bugs</td><td>${summary.issues.breakdown.byType.BUG || 0}</td></tr>
                <tr><td>Vulnerabilities</td><td>${summary.issues.breakdown.byType.VULNERABILITY || 0}</td></tr>
                <tr><td>Security Hotspots</td><td>${summary.issues.breakdown.byType.SECURITY_HOTSPOT || 0}</td></tr>
                <tr><td>Code Smells</td><td>${summary.issues.breakdown.byType.CODE_SMELL || 0}</td></tr>
            </tbody>
        </table>

        <h3>⚠️ Severity Breakdown</h3>
        <table class="issues-table">
            <thead>
                <tr><th>Severity</th><th>Count</th></tr>
            </thead>
            <tbody>
                <tr><td>Blocker</td><td>${summary.issues.breakdown.bySeverity.BLOCKER || 0}</td></tr>
                <tr><td>Critical</td><td>${summary.issues.breakdown.bySeverity.CRITICAL || 0}</td></tr>
                <tr><td>Major</td><td>${summary.issues.breakdown.bySeverity.MAJOR || 0}</td></tr>
                <tr><td>Minor</td><td>${summary.issues.breakdown.bySeverity.MINOR || 0}</td></tr>
                <tr><td>Info</td><td>${summary.issues.breakdown.bySeverity.INFO || 0}</td></tr>
            </tbody>
        </table>

        <div style="text-align: center; margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
            <p>🔗 <a href="${`${this.baseUrl}/dashboard?id=${this.projectKey}`}" target="_blank">View Full Report in SonarQube Dashboard</a></p>
        </div>
    </div>
</body>
</html>
    `;
  }

  async cleanup() {
    try {
      logger.info('🧹 Cleaning up SonarQube integration...');
      this.initialized = false;
      this.metrics.clear();
      this.qualityGateStatus = null;
      logger.info('✅ SonarQube integration cleanup completed');
    } catch (error) {
      logger.error('❌ SonarQube cleanup failed:', error.message);
    }
  }

  isReady() {
    return this.initialized;
  }

  getMetrics() {
    return Object.fromEntries(this.metrics);
  }

  getQualityGateStatus() {
    return this.qualityGateStatus;
  }
}

module.exports = SonarQubeIntegration;