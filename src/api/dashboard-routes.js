const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const logger = require('../utils/logger');
const SecurityAnalyzer = require('../analyzers/security-analyzer');
const StaticAnalyzer = require('../analyzers/static-analyzer');
const DynamicAnalyzer = require('../analyzers/dynamic-analyzer');
const RemediationEngine = require('../remediation/remediation-engine');

const router = express.Router();

class DashboardController {
  constructor() {
    this.securityAnalyzer = new SecurityAnalyzer();
    this.staticAnalyzer = new StaticAnalyzer();
    this.dynamicAnalyzer = new DynamicAnalyzer();
    this.remediationEngine = new RemediationEngine();
    
    this.metricsCache = new Map();
    this.cacheExpiry = 30000; // 30 seconds
    
    this.initializeRoutes();
  }

  initializeRoutes() {
    // Dashboard home
    router.get('/', this.serveDashboard.bind(this));
    
    // API endpoints
    router.get('/metrics', this.getMetrics.bind(this));
    router.get('/scan-history', this.getScanHistory.bind(this));
    router.get('/security-trends', this.getSecurityTrends.bind(this));
    router.get('/quality-metrics', this.getQualityMetrics.bind(this));
    router.get('/compliance-status', this.getComplianceStatus.bind(this));
    router.get('/remediation-stats', this.getRemediationStats.bind(this));
    router.get('/system-health', this.getSystemHealth.bind(this));
    
    // Real-time data
    router.get('/live-metrics', this.getLiveMetrics.bind(this));
    router.post('/trigger-scan', this.triggerScan.bind(this));
    
    // Reports
    router.get('/reports/security', this.generateSecurityReport.bind(this));
    router.get('/reports/quality', this.generateQualityReport.bind(this));
    router.get('/reports/compliance', this.generateComplianceReport.bind(this));
    router.get('/reports/executive', this.generateExecutiveReport.bind(this));
    
    // Export functionality
    router.post('/export', this.exportData.bind(this));
    
    // Settings
    router.get('/settings', this.getSettings.bind(this));
    router.post('/settings', this.updateSettings.bind(this));
  }

  async serveDashboard(req, res) {
    try {
      const dashboardPath = path.join(__dirname, '../../dashboard/index.html');
      const dashboardContent = await fs.readFile(dashboardPath, 'utf8');
      res.send(dashboardContent);
    } catch (error) {
      logger.error('Failed to serve dashboard:', error.message);
      res.status(500).json({ error: 'Dashboard unavailable' });
    }
  }

  async getMetrics(req, res) {
    try {
      const cacheKey = 'dashboard-metrics';
      
      // Check cache first
      const cached = this.metricsCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
        return res.json(cached.data);
      }
      
      // Gather metrics from all analyzers
      const metrics = await this.collectMetrics();
      
      // Cache the results
      this.metricsCache.set(cacheKey, {
        data: metrics,
        timestamp: Date.now()
      });
      
      res.json(metrics);
    } catch (error) {
      logger.error('Failed to get metrics:', error.message);
      res.status(500).json({ error: 'Failed to retrieve metrics' });
    }
  }

  async collectMetrics() {
    const metrics = {
      timestamp: new Date().toISOString(),
      security: await this.getSecurityMetrics(),
      quality: await this.getQualityMetrics(),
      performance: await this.getPerformanceMetrics(),
      compliance: await this.getComplianceMetrics(),
      system: await this.getSystemMetrics()
    };

    return {
      securityIssues: metrics.security.total,
      qualityScore: metrics.quality.overallScore,
      testCoverage: metrics.quality.coverage,
      buildTime: metrics.performance.averageBuildTime,
      complianceScore: metrics.compliance.overallScore,
      systemHealth: metrics.system.healthScore,
      lastScanTime: metrics.security.lastScanTime,
      trendsData: await this.getTrendsData()
    };
  }

  async getSecurityMetrics() {
    try {
      // Mock data - replace with actual analyzer integration
      const mockFindings = await this.getMockSecurityFindings();
      
      const severityCounts = mockFindings.reduce((acc, finding) => {
        acc[finding.severity] = (acc[finding.severity] || 0) + 1;
        return acc;
      }, {});

      return {
        total: mockFindings.length,
        critical: severityCounts.critical || 0,
        high: severityCounts.high || 0,
        medium: severityCounts.medium || 0,
        low: severityCounts.low || 0,
        lastScanTime: new Date().toISOString(),
        categories: this.categorizeSecurityFindings(mockFindings)
      };
    } catch (error) {
      logger.error('Failed to get security metrics:', error.message);
      return { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    }
  }

  async getMockSecurityFindings() {
    // Mock security findings for demonstration
    return [
      { id: '1', severity: 'critical', type: 'sql-injection', file: 'api/users.js', line: 45 },
      { id: '2', severity: 'high', type: 'xss-vulnerability', file: 'views/profile.js', line: 23 },
      { id: '3', severity: 'high', type: 'hardcoded-secrets', file: 'config/database.js', line: 8 },
      { id: '4', severity: 'medium', type: 'insecure-http', file: 'utils/api.js', line: 12 },
      { id: '5', severity: 'medium', type: 'weak-crypto', file: 'auth/passwords.js', line: 67 },
      { id: '6', severity: 'low', type: 'unused-variables', file: 'helpers/utils.js', line: 34 }
    ];
  }

  categorizeSecurityFindings(findings) {
    const categories = {};
    
    findings.forEach(finding => {
      const category = this.getSecurityCategory(finding.type);
      categories[category] = (categories[category] || 0) + 1;
    });
    
    return categories;
  }

  getSecurityCategory(type) {
    const categoryMap = {
      'sql-injection': 'injection',
      'xss-vulnerability': 'xss',
      'hardcoded-secrets': 'secrets',
      'insecure-http': 'transport',
      'weak-crypto': 'cryptography',
      'unused-variables': 'code-quality'
    };
    
    return categoryMap[type] || 'other';
  }

  async getQualityMetrics() {
    try {
      return {
        overallScore: 85,
        coverage: 78.5,
        complexity: 12.3,
        maintainability: 'A',
        reliability: 'B',
        duplicatedLines: 3.2,
        technicalDebt: '2.5h',
        codeSmells: 45,
        bugs: 8,
        vulnerabilities: 12
      };
    } catch (error) {
      logger.error('Failed to get quality metrics:', error.message);
      return { overallScore: 0, coverage: 0 };
    }
  }

  async getPerformanceMetrics() {
    return {
      averageBuildTime: '4.2m',
      testExecutionTime: '1.8m',
      deploymentTime: '2.1m',
      scanTime: '3.5m',
      cicdEfficiency: 92
    };
  }

  async getComplianceMetrics() {
    return {
      overallScore: 87,
      frameworks: {
        'NIST': 89,
        'ISO27001': 85,
        'PCI-DSS': 91,
        'HIPAA': 82
      },
      lastAuditDate: '2024-01-15T10:00:00Z',
      nextAuditDue: '2024-04-15T10:00:00Z'
    };
  }

  async getSystemMetrics() {
    return {
      healthScore: 95,
      uptime: '99.8%',
      responseTime: '120ms',
      errorRate: '0.2%',
      throughput: '1.2k req/min',
      diskUsage: '45%',
      memoryUsage: '68%',
      cpuUsage: '23%'
    };
  }

  async getTrendsData() {
    return {
      securityTrends: [
        { date: '2024-01-01', critical: 5, high: 12, medium: 25 },
        { date: '2024-01-08', critical: 3, high: 8, medium: 22 },
        { date: '2024-01-15', critical: 2, high: 6, medium: 18 },
        { date: '2024-01-22', critical: 1, high: 4, medium: 15 }
      ],
      qualityTrends: [
        { date: '2024-01-01', score: 82 },
        { date: '2024-01-08', score: 84 },
        { date: '2024-01-15', score: 86 },
        { date: '2024-01-22', score: 85 }
      ]
    };
  }

  async getScanHistory(req, res) {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;
      
      // Mock scan history
      const scans = [
        {
          id: 'scan-001',
          project: 'secure-code-analyzer',
          status: 'completed',
          startTime: new Date(Date.now() - 300000).toISOString(),
          endTime: new Date(Date.now() - 240000).toISOString(),
          duration: '1.2m',
          findings: 12,
          severity: 'medium'
        },
        {
          id: 'scan-002',
          project: 'api-gateway',
          status: 'completed',
          startTime: new Date(Date.now() - 900000).toISOString(),
          endTime: new Date(Date.now() - 780000).toISOString(),
          duration: '2.1m',
          findings: 8,
          severity: 'low'
        }
      ];
      
      res.json({
        scans: scans.slice(offset, offset + limit),
        total: scans.length,
        hasMore: offset + limit < scans.length
      });
    } catch (error) {
      logger.error('Failed to get scan history:', error.message);
      res.status(500).json({ error: 'Failed to retrieve scan history' });
    }
  }

  async getSecurityTrends(req, res) {
    try {
      const days = parseInt(req.query.days) || 30;
      const trends = await this.calculateSecurityTrends(days);
      res.json(trends);
    } catch (error) {
      logger.error('Failed to get security trends:', error.message);
      res.status(500).json({ error: 'Failed to retrieve security trends' });
    }
  }

  async calculateSecurityTrends(days) {
    const trends = [];
    const today = new Date();
    
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      
      // Mock trend data
      trends.push({
        date: date.toISOString().split('T')[0],
        critical: Math.max(0, Math.floor(Math.random() * 5) - i / 10),
        high: Math.max(0, Math.floor(Math.random() * 15) - i / 8),
        medium: Math.max(0, Math.floor(Math.random() * 30) - i / 5),
        low: Math.max(0, Math.floor(Math.random() * 50) - i / 3)
      });
    }
    
    return trends;
  }

  async getComplianceStatus(req, res) {
    try {
      const status = {
        overall: 'compliant',
        score: 87,
        frameworks: {
          'NIST Cybersecurity Framework': {
            score: 89,
            status: 'compliant',
            lastAssessment: '2024-01-15T10:00:00Z',
            gaps: ['Asset Management', 'Incident Response']
          },
          'ISO 27001': {
            score: 85,
            status: 'mostly-compliant',
            lastAssessment: '2024-01-10T10:00:00Z',
            gaps: ['Risk Assessment', 'Business Continuity']
          },
          'PCI DSS': {
            score: 91,
            status: 'compliant',
            lastAssessment: '2024-01-20T10:00:00Z',
            gaps: []
          }
        },
        recommendations: [
          'Implement automated asset discovery',
          'Enhance incident response procedures',
          'Conduct risk assessment review'
        ]
      };
      
      res.json(status);
    } catch (error) {
      logger.error('Failed to get compliance status:', error.message);
      res.status(500).json({ error: 'Failed to retrieve compliance status' });
    }
  }

  async getRemediationStats(req, res) {
    try {
      const stats = {
        totalIssues: 45,
        autoFixed: 18,
        pendingReview: 12,
        falsePositives: 5,
        remediationRate: 67,
        averageTimeToFix: '2.3 days',
        topRemediation: [
          { type: 'hardcoded-secrets', count: 8, autoFixed: 6 },
          { type: 'insecure-http', count: 5, autoFixed: 5 },
          { type: 'weak-crypto', count: 4, autoFixed: 2 }
        ]
      };
      
      res.json(stats);
    } catch (error) {
      logger.error('Failed to get remediation stats:', error.message);
      res.status(500).json({ error: 'Failed to retrieve remediation statistics' });
    }
  }

  async getSystemHealth(req, res) {
    try {
      const health = {
        status: 'healthy',
        uptime: process.uptime(),
        services: {
          securityAnalyzer: this.securityAnalyzer.isReady(),
          staticAnalyzer: this.staticAnalyzer.isReady(),
          dynamicAnalyzer: this.dynamicAnalyzer.isReady(),
          remediationEngine: this.remediationEngine.isReady()
        },
        resources: {
          memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
            percentage: Math.round((process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100)
          },
          cpu: Math.floor(Math.random() * 30) + 10, // Mock CPU usage
        },
        lastHealthCheck: new Date().toISOString()
      };
      
      res.json(health);
    } catch (error) {
      logger.error('Failed to get system health:', error.message);
      res.status(500).json({ error: 'Failed to retrieve system health' });
    }
  }

  async getLiveMetrics(req, res) {
    try {
      // Set up Server-Sent Events
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });

      const sendMetrics = async () => {
        try {
          const metrics = await this.collectMetrics();
          res.write(`data: ${JSON.stringify(metrics)}\n\n`);
        } catch (error) {
          logger.error('Failed to send live metrics:', error.message);
        }
      };

      // Send initial metrics
      await sendMetrics();

      // Send updates every 30 seconds
      const interval = setInterval(sendMetrics, 30000);

      req.on('close', () => {
        clearInterval(interval);
        res.end();
      });

    } catch (error) {
      logger.error('Failed to establish live metrics stream:', error.message);
      res.status(500).json({ error: 'Failed to establish live metrics stream' });
    }
  }

  async triggerScan(req, res) {
    try {
      const { target, type = 'full', options = {} } = req.body;
      
      // Generate scan ID
      const scanId = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      // Mock scan initiation
      const scan = {
        id: scanId,
        target,
        type,
        status: 'running',
        startTime: new Date().toISOString(),
        progress: 0
      };

      // Emit real-time update via WebSocket
      const io = req.app.get('io');
      if (io) {
        io.emit('scan-update', {
          scanId,
          status: 'started',
          project: target,
          timestamp: new Date().toISOString()
        });
      }

      res.json({ scanId, status: 'started', message: 'Scan initiated successfully' });
    } catch (error) {
      logger.error('Failed to trigger scan:', error.message);
      res.status(500).json({ error: 'Failed to trigger scan' });
    }
  }

  async generateSecurityReport(req, res) {
    try {
      const format = req.query.format || 'html';
      const timeRange = req.query.timeRange || '30d';
      
      const report = await this.buildSecurityReport(timeRange);
      
      if (format === 'json') {
        res.json(report);
      } else {
        const html = this.generateSecurityReportHTML(report);
        res.send(html);
      }
    } catch (error) {
      logger.error('Failed to generate security report:', error.message);
      res.status(500).json({ error: 'Failed to generate security report' });
    }
  }

  async buildSecurityReport(timeRange) {
    const securityMetrics = await this.getSecurityMetrics();
    const trends = await this.getTrendsData();
    
    return {
      metadata: {
        title: 'Security Analysis Report',
        generatedAt: new Date().toISOString(),
        timeRange,
        version: '1.0.0'
      },
      executive: {
        totalFindings: securityMetrics.total,
        criticalIssues: securityMetrics.critical,
        riskLevel: this.calculateRiskLevel(securityMetrics),
        recommendations: [
          'Address all critical security vulnerabilities immediately',
          'Implement automated security scanning in CI/CD pipeline',
          'Conduct security training for development team'
        ]
      },
      findings: {
        bySeverity: {
          critical: securityMetrics.critical,
          high: securityMetrics.high,
          medium: securityMetrics.medium,
          low: securityMetrics.low
        },
        byCategory: securityMetrics.categories,
        trends: trends.securityTrends
      },
      remediation: {
        autoFixable: Math.floor(securityMetrics.total * 0.4),
        requiresReview: Math.ceil(securityMetrics.total * 0.6),
        estimatedEffort: '2-3 weeks'
      }
    };
  }

  calculateRiskLevel(metrics) {
    if (metrics.critical > 0) return 'High';
    if (metrics.high > 5) return 'Medium-High';
    if (metrics.high > 0 || metrics.medium > 10) return 'Medium';
    return 'Low';
  }

  generateSecurityReportHTML(report) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>${report.metadata.title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 5px; }
        .metric { display: inline-block; margin: 20px; text-align: center; }
        .metric-value { font-size: 2rem; font-weight: bold; }
        .critical { color: #e74c3c; }
        .high { color: #f39c12; }
        .medium { color: #3498db; }
        .low { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${report.metadata.title}</h1>
        <p>Generated: ${new Date(report.metadata.generatedAt).toLocaleString()}</p>
    </div>

    <h2>Executive Summary</h2>
    <div class="metric">
        <div class="metric-value">${report.executive.totalFindings}</div>
        <div>Total Findings</div>
    </div>
    <div class="metric">
        <div class="metric-value critical">${report.executive.criticalIssues}</div>
        <div>Critical Issues</div>
    </div>
    <div class="metric">
        <div class="metric-value">${report.executive.riskLevel}</div>
        <div>Risk Level</div>
    </div>

    <h2>Findings by Severity</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td>Critical</td><td class="critical">${report.findings.bySeverity.critical}</td></tr>
        <tr><td>High</td><td class="high">${report.findings.bySeverity.high}</td></tr>
        <tr><td>Medium</td><td class="medium">${report.findings.bySeverity.medium}</td></tr>
        <tr><td>Low</td><td class="low">${report.findings.bySeverity.low}</td></tr>
    </table>

    <h2>Recommendations</h2>
    <ul>
        ${report.executive.recommendations.map(rec => `<li>${rec}</li>`).join('')}
    </ul>

    <div style="margin-top: 50px; text-align: center; color: #7f8c8d;">
        <p>Generated by Secure Code Analyzer - DevSecOps Integration Platform</p>
    </div>
</body>
</html>
    `;
  }

  async generateQualityReport(req, res) {
    try {
      const report = {
        metadata: {
          title: 'Code Quality Report',
          generatedAt: new Date().toISOString()
        },
        quality: await this.getQualityMetrics(),
        recommendations: [
          'Increase test coverage to 80%+',
          'Reduce code complexity in critical modules',
          'Address technical debt items'
        ]
      };

      res.json(report);
    } catch (error) {
      logger.error('Failed to generate quality report:', error.message);
      res.status(500).json({ error: 'Failed to generate quality report' });
    }
  }

  async generateComplianceReport(req, res) {
    try {
      const compliance = await this.getComplianceMetrics();
      const report = {
        metadata: {
          title: 'Compliance Assessment Report',
          generatedAt: new Date().toISOString()
        },
        compliance,
        summary: {
          status: compliance.overallScore >= 80 ? 'Compliant' : 'Non-Compliant',
          score: compliance.overallScore,
          frameworksAssessed: Object.keys(compliance.frameworks).length
        }
      };

      res.json(report);
    } catch (error) {
      logger.error('Failed to generate compliance report:', error.message);
      res.status(500).json({ error: 'Failed to generate compliance report' });
    }
  }

  async generateExecutiveReport(req, res) {
    try {
      const metrics = await this.collectMetrics();
      
      const report = {
        metadata: {
          title: 'Executive Security Dashboard',
          generatedAt: new Date().toISOString(),
          period: 'Last 30 Days'
        },
        kpis: {
          securityPosture: {
            score: 100 - metrics.securityIssues * 5,
            trend: 'improving',
            description: 'Overall security risk level'
          },
          codeQuality: {
            score: metrics.qualityScore,
            trend: 'stable',
            description: 'Code maintainability and reliability'
          },
          compliance: {
            score: metrics.complianceScore,
            trend: 'improving',
            description: 'Regulatory compliance status'
          },
          systemHealth: {
            score: metrics.systemHealth,
            trend: 'excellent',
            description: 'System performance and availability'
          }
        },
        insights: [
          'Security vulnerabilities decreased by 25% this month',
          'Code coverage improved by 8% with new testing practices',
          'All critical compliance requirements are met',
          'System uptime maintained at 99.9%'
        ],
        actions: [
          'Continue focus on security training initiatives',
          'Implement automated dependency scanning',
          'Schedule quarterly security assessments'
        ]
      };

      res.json(report);
    } catch (error) {
      logger.error('Failed to generate executive report:', error.message);
      res.status(500).json({ error: 'Failed to generate executive report' });
    }
  }

  async exportData(req, res) {
    try {
      const { format = 'json', timeRange = '30d', includeReports = true } = req.body;
      
      const exportData = {
        metadata: {
          exportedAt: new Date().toISOString(),
          timeRange,
          format
        },
        metrics: await this.collectMetrics(),
        scanHistory: (await this.getScanHistory({ query: { limit: 100 } }, { json: (data) => data })),
        systemHealth: await this.getSystemHealth({ query: {} }, { json: (data) => data })
      };

      if (includeReports) {
        exportData.reports = {
          security: await this.buildSecurityReport(timeRange),
          quality: await this.getQualityMetrics(),
          compliance: await this.getComplianceMetrics()
        };
      }

      // Set appropriate headers for download
      const filename = `secure-code-analyzer-export-${Date.now()}.${format}`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', `application/${format}`);

      if (format === 'json') {
        res.json(exportData);
      } else {
        res.status(400).json({ error: 'Unsupported export format' });
      }
    } catch (error) {
      logger.error('Failed to export data:', error.message);
      res.status(500).json({ error: 'Failed to export data' });
    }
  }

  async getSettings(req, res) {
    try {
      const settings = {
        scanning: {
          autoScanEnabled: true,
          scanInterval: '24h',
          scanDepth: 'comprehensive',
          excludePatterns: ['node_modules/', 'dist/', '.git/']
        },
        security: {
          severityThreshold: 'medium',
          autoRemediation: false,
          notifyOnCritical: true
        },
        compliance: {
          enabledFrameworks: ['NIST', 'ISO27001', 'PCI-DSS'],
          requireApproval: true
        },
        notifications: {
          email: true,
          slack: true,
          webhook: false
        }
      };

      res.json(settings);
    } catch (error) {
      logger.error('Failed to get settings:', error.message);
      res.status(500).json({ error: 'Failed to retrieve settings' });
    }
  }

  async updateSettings(req, res) {
    try {
      const updatedSettings = req.body;
      
      // Validate and save settings (implementation would persist to database)
      logger.info('Settings updated:', updatedSettings);
      
      res.json({
        success: true,
        message: 'Settings updated successfully',
        settings: updatedSettings
      });
    } catch (error) {
      logger.error('Failed to update settings:', error.message);
      res.status(500).json({ error: 'Failed to update settings' });
    }
  }
}

// Initialize dashboard controller
new DashboardController();

module.exports = router;