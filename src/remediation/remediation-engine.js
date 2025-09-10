const fs = require('fs').promises;
const path = require('path');
const logger = require('../utils/logger');
const SecurityAnalyzer = require('../analyzers/security-analyzer');

class RemediationEngine {
  constructor(options = {}) {
    this.options = {
      autoApplyFixes: options.autoApplyFixes || false,
      maxFixesPerFile: options.maxFixesPerFile || 10,
      backupOriginal: options.backupOriginal !== false,
      riskThreshold: options.riskThreshold || 'medium',
      aiModel: options.aiModel || 'gpt-3.5-turbo',
      ...options
    };
    
    this.remediationRules = new Map();
    this.fixHistory = [];
    this.suggestions = new Map();
    this.initialized = false;
    
    this.initializeRemediationRules();
  }

  async initialize() {
    try {
      logger.info('🔧 Initializing Remediation Engine...');
      
      // Initialize AI service (placeholder for actual AI integration)
      await this.initializeAIService();
      
      // Load custom remediation patterns
      await this.loadCustomPatterns();
      
      this.initialized = true;
      logger.info('✅ Remediation Engine initialized successfully');
      
      return true;
    } catch (error) {
      logger.error('❌ Failed to initialize Remediation Engine:', error.message);
      throw error;
    }
  }

  async initializeAIService() {
    // Placeholder for AI service initialization
    // In production, integrate with OpenAI, Azure OpenAI, or local AI models
    this.aiService = {
      generateSuggestion: async (vulnerability, code, context) => {
        return this.generateAISuggestion(vulnerability, code, context);
      }
    };
  }

  async loadCustomPatterns() {
    try {
      const patternsPath = path.join(__dirname, '../config/remediation-patterns.json');
      if (await this.fileExists(patternsPath)) {
        const patterns = JSON.parse(await fs.readFile(patternsPath, 'utf8'));
        
        Object.entries(patterns).forEach(([key, pattern]) => {
          this.remediationRules.set(key, pattern);
        });
        
        logger.info(`✅ Loaded ${Object.keys(patterns).length} custom remediation patterns`);
      }
    } catch (error) {
      logger.warn('Could not load custom patterns:', error.message);
    }
  }

  initializeRemediationRules() {
    // SQL Injection fixes
    this.remediationRules.set('sql-injection', {
      type: 'security',
      severity: 'critical',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Replace dynamic SQL with parameterized queries',
      patterns: [
        {
          match: /query\s*\(\s*[`'"](.*?)\$\{.*?\}.*?[`'"]\s*\)/g,
          replace: 'query($1, [parameters])',
          explanation: 'Use parameterized queries to prevent SQL injection'
        },
        {
          match: /db\.query\s*\(\s*[`'"](.+?)[`'"]\s*\+\s*.+?\)/g,
          replace: 'db.query($1, [parameters])',
          explanation: 'Replace string concatenation with parameterized queries'
        }
      ],
      examples: [
        {
          before: "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
          after: "db.query('SELECT * FROM users WHERE id = ?', [userId])",
          explanation: "Use parameterized queries to prevent SQL injection attacks"
        }
      ]
    });

    // XSS fixes
    this.remediationRules.set('xss-vulnerability', {
      type: 'security',
      severity: 'high',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Add input sanitization and output encoding',
      patterns: [
        {
          match: /innerHTML\s*=\s*[^;]+/g,
          replace: 'textContent = sanitizeInput($&)',
          explanation: 'Use textContent instead of innerHTML for user data'
        },
        {
          match: /document\.write\s*\(\s*[^)]+\)/g,
          replace: 'sanitizedElement.textContent = sanitizeInput($1)',
          explanation: 'Replace document.write with safe DOM manipulation'
        }
      ],
      examples: [
        {
          before: "element.innerHTML = userInput",
          after: "element.textContent = DOMPurify.sanitize(userInput)",
          explanation: "Sanitize user input before inserting into DOM"
        }
      ]
    });

    // Hardcoded secrets
    this.remediationRules.set('hardcoded-secrets', {
      type: 'security',
      severity: 'critical',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Replace hardcoded secrets with environment variables',
      patterns: [
        {
          match: /(password|secret|key|token)\s*[:=]\s*['"]((?!\$\{).+?)['"]/gi,
          replace: '$1: process.env.${1.toUpperCase()}',
          explanation: 'Move secrets to environment variables'
        },
        {
          match: /apiKey\s*[:=]\s*['"]((?!process\.env).+?)['"]/g,
          replace: 'apiKey: process.env.API_KEY',
          explanation: 'Use environment variables for API keys'
        }
      ],
      examples: [
        {
          before: "const apiKey = 'abc123def456'",
          after: "const apiKey = process.env.API_KEY",
          explanation: "Store API keys in environment variables, not source code"
        }
      ]
    });

    // Weak cryptography
    this.remediationRules.set('weak-crypto', {
      type: 'security',
      severity: 'high',
      autoFixable: true,
      riskLevel: 'medium',
      description: 'Replace weak cryptographic algorithms with secure alternatives',
      patterns: [
        {
          match: /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/g,
          replace: "crypto.createHash('sha256')",
          explanation: 'Replace MD5 with SHA-256 for cryptographic hashing'
        },
        {
          match: /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/g,
          replace: "crypto.createHash('sha256')",
          explanation: 'Replace SHA-1 with SHA-256 for better security'
        }
      ],
      examples: [
        {
          before: "crypto.createHash('md5')",
          after: "crypto.createHash('sha256')",
          explanation: "Use SHA-256 instead of MD5 for cryptographic security"
        }
      ]
    });

    // Insecure HTTP
    this.remediationRules.set('insecure-http', {
      type: 'security',
      severity: 'medium',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Replace HTTP with HTTPS for secure communication',
      patterns: [
        {
          match: /['"]http:\/\/(?!localhost|127\.0\.0\.1)/g,
          replace: '"https://',
          explanation: 'Use HTTPS for secure communication'
        }
      ],
      examples: [
        {
          before: "const apiUrl = 'http://api.example.com'",
          after: "const apiUrl = 'https://api.example.com'",
          explanation: "Always use HTTPS for external API communications"
        }
      ]
    });

    // Unsafe regular expressions
    this.remediationRules.set('regex-dos', {
      type: 'security',
      severity: 'medium',
      autoFixable: false,
      riskLevel: 'high',
      description: 'Review regular expressions for ReDoS vulnerabilities',
      patterns: [
        {
          match: /\/\(\.\*\)\+.*?\//g,
          replace: null,
          explanation: 'This regex pattern may be vulnerable to ReDoS attacks'
        }
      ],
      examples: [
        {
          before: "/^(a+)+$/",
          after: "/^a+$/",
          explanation: "Avoid nested quantifiers that can cause exponential backtracking"
        }
      ]
    });

    // Insufficient input validation
    this.remediationRules.set('input-validation', {
      type: 'security',
      severity: 'medium',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Add input validation and sanitization',
      patterns: [
        {
          match: /app\.(get|post|put|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*\([^)]*\)\s*=>\s*\{/g,
          replace: '$&\n  // TODO: Add input validation',
          explanation: 'Add input validation for API endpoints'
        }
      ],
      examples: [
        {
          before: "app.post('/users', (req, res) => { const user = req.body; })",
          after: `app.post('/users', [
  body('email').isEmail().normalizeEmail(),
  body('name').trim().isLength({ min: 1, max: 100 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const user = req.body;
})`,
          explanation: "Always validate and sanitize user input in API endpoints"
        }
      ]
    });

    // Unsafe file operations
    this.remediationRules.set('path-traversal', {
      type: 'security',
      severity: 'high',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Prevent path traversal attacks in file operations',
      patterns: [
        {
          match: /fs\.(readFile|writeFile)\s*\(\s*req\.(body|params|query)\.[\w.]+/g,
          replace: 'fs.$1(path.resolve(safeDir, path.basename($2)))',
          explanation: 'Validate file paths to prevent directory traversal'
        }
      ],
      examples: [
        {
          before: "fs.readFile(req.params.filename, callback)",
          after: "fs.readFile(path.resolve(uploadsDir, path.basename(req.params.filename)), callback)",
          explanation: "Always validate and sanitize file paths to prevent directory traversal"
        }
      ]
    });

    // Code quality fixes
    this.remediationRules.set('unused-variables', {
      type: 'quality',
      severity: 'low',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Remove unused variables',
      patterns: [
        {
          match: /^(\s*)(?:const|let|var)\s+(\w+)\s*=.*?;\s*$/gm,
          replace: null, // Requires context analysis
          explanation: 'Remove unused variables to improve code quality'
        }
      ]
    });

    // Performance fixes
    this.remediationRules.set('inefficient-loops', {
      type: 'performance',
      severity: 'low',
      autoFixable: true,
      riskLevel: 'low',
      description: 'Optimize loop performance',
      patterns: [
        {
          match: /for\s*\(\s*let\s+(\w+)\s*=\s*0;\s*\1\s*<\s*(\w+)\.length;\s*\1\+\+\s*\)/g,
          replace: 'for (let $1 = 0, len = $2.length; $1 < len; $1++)',
          explanation: 'Cache array length in loops for better performance'
        }
      ]
    });
  }

  async analyzeAndRemediate(filePath, securityFindings) {
    try {
      logger.info(`🔍 Analyzing remediation options for: ${filePath}`);
      
      const fileContent = await fs.readFile(filePath, 'utf8');
      const remediationPlan = await this.createRemediationPlan(
        filePath,
        fileContent,
        securityFindings
      );
      
      if (this.options.autoApplyFixes) {
        const appliedFixes = await this.applyAutomaticFixes(filePath, fileContent, remediationPlan);
        return {
          plan: remediationPlan,
          appliedFixes,
          status: 'fixes-applied'
        };
      } else {
        return {
          plan: remediationPlan,
          suggestions: await this.generateSuggestions(remediationPlan),
          status: 'suggestions-only'
        };
      }
      
    } catch (error) {
      logger.error(`❌ Remediation analysis failed for ${filePath}:`, error.message);
      throw error;
    }
  }

  async createRemediationPlan(filePath, content, findings) {
    const plan = {
      file: filePath,
      timestamp: new Date().toISOString(),
      findings: findings.length,
      fixes: [],
      suggestions: [],
      riskAssessment: {}
    };
    
    for (const finding of findings) {
      const remediationRule = this.remediationRules.get(finding.rule);
      
      if (remediationRule) {
        const fix = await this.createFix(finding, content, remediationRule);
        
        if (fix.autoFixable && this.isFixSafe(fix)) {
          plan.fixes.push(fix);
        } else {
          const suggestion = await this.createSuggestion(finding, content, remediationRule);
          plan.suggestions.push(suggestion);
        }
      } else {
        // Use AI to generate suggestions for unknown rules
        const aiSuggestion = await this.generateAISuggestion(finding, content);
        plan.suggestions.push(aiSuggestion);
      }
    }
    
    plan.riskAssessment = this.assessRemediationRisk(plan);
    
    return plan;
  }

  async createFix(finding, content, rule) {
    const fix = {
      id: `fix-${finding.id}`,
      rule: finding.rule,
      severity: finding.severity,
      description: rule.description,
      autoFixable: rule.autoFixable,
      riskLevel: rule.riskLevel,
      location: finding.location,
      changes: []
    };
    
    // Apply pattern-based fixes
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        if (pattern.match && pattern.replace) {
          const matches = [...content.matchAll(pattern.match)];
          
          for (const match of matches) {
            const change = {
              type: 'replace',
              original: match[0],
              replacement: this.processReplacement(pattern.replace, match),
              line: this.getLineNumber(content, match.index),
              explanation: pattern.explanation
            };
            
            fix.changes.push(change);
          }
        }
      }
    }
    
    return fix;
  }

  async createSuggestion(finding, content, rule) {
    const suggestion = {
      id: `suggestion-${finding.id}`,
      rule: finding.rule,
      severity: finding.severity,
      description: rule.description,
      location: finding.location,
      recommendations: [],
      examples: rule.examples || []
    };
    
    // Generate contextual recommendations
    const context = this.extractContext(content, finding.location);
    suggestion.recommendations = await this.generateContextualRecommendations(
      finding,
      context,
      rule
    );
    
    return suggestion;
  }

  processReplacement(replacement, match) {
    // Handle special replacement patterns
    let result = replacement;
    
    // Replace $& with full match
    result = result.replace(/\$&/g, match[0]);
    
    // Replace $1, $2, etc. with capture groups
    for (let i = 1; i < match.length; i++) {
      result = result.replace(new RegExp(`\\$${i}`, 'g'), match[i] || '');
    }
    
    // Process function calls in replacement
    result = result.replace(/\$\{(.+?)\}/g, (_, code) => {
      try {
        // Simple expression evaluation (extend as needed)
        if (code.includes('toUpperCase()')) {
          const varName = code.replace('.toUpperCase()', '');
          const matchIndex = parseInt(varName) || 1;
          return (match[matchIndex] || '').toUpperCase();
        }
        return code;
      } catch (error) {
        return code;
      }
    });
    
    return result;
  }

  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  extractContext(content, location) {
    const lines = content.split('\n');
    const startLine = Math.max(0, location.line - 3);
    const endLine = Math.min(lines.length, location.line + 3);
    
    return {
      before: lines.slice(startLine, location.line - 1).join('\n'),
      current: lines[location.line - 1] || '',
      after: lines.slice(location.line, endLine).join('\n'),
      lineNumber: location.line
    };
  }

  async generateContextualRecommendations(finding, context, rule) {
    const recommendations = [];
    
    // Base recommendation from rule
    recommendations.push({
      priority: 'high',
      action: rule.description,
      details: `Address ${finding.rule} at line ${context.lineNumber}`,
      effort: this.estimateEffort(rule),
      impact: this.estimateImpact(finding.severity)
    });
    
    // Add specific recommendations based on context
    if (finding.rule === 'sql-injection') {
      recommendations.push({
        priority: 'high',
        action: 'Implement parameterized queries',
        details: 'Use prepared statements or ORM query builders to prevent SQL injection',
        effort: 'medium',
        impact: 'high'
      });
    } else if (finding.rule === 'xss-vulnerability') {
      recommendations.push({
        priority: 'high',
        action: 'Add input sanitization',
        details: 'Use libraries like DOMPurify to sanitize user input before rendering',
        effort: 'low',
        impact: 'high'
      });
    } else if (finding.rule === 'hardcoded-secrets') {
      recommendations.push({
        priority: 'critical',
        action: 'Move secrets to environment variables',
        details: 'Store sensitive data in environment variables or secure secret management systems',
        effort: 'low',
        impact: 'critical'
      });
    }
    
    return recommendations;
  }

  estimateEffort(rule) {
    if (rule.autoFixable && rule.riskLevel === 'low') return 'low';
    if (rule.type === 'security') return 'medium';
    return 'high';
  }

  estimateImpact(severity) {
    const impactMap = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low'
    };
    return impactMap[severity] || 'medium';
  }

  isFixSafe(fix) {
    // Assess if the fix is safe to apply automatically
    return fix.riskLevel === 'low' && 
           fix.changes.length <= this.options.maxFixesPerFile &&
           !this.containsComplexPatterns(fix);
  }

  containsComplexPatterns(fix) {
    // Check for patterns that might require human review
    const complexPatterns = [
      /function\s*\(/,
      /class\s+\w+/,
      /async\s+function/,
      /try\s*\{[\s\S]*catch/
    ];
    
    return fix.changes.some(change => 
      complexPatterns.some(pattern => 
        pattern.test(change.original) || pattern.test(change.replacement)
      )
    );
  }

  assessRemediationRisk(plan) {
    let totalRisk = 0;
    let totalFixes = plan.fixes.length + plan.suggestions.length;
    
    plan.fixes.forEach(fix => {
      switch (fix.riskLevel) {
        case 'low': totalRisk += 1; break;
        case 'medium': totalRisk += 3; break;
        case 'high': totalRisk += 5; break;
      }
    });
    
    plan.suggestions.forEach(suggestion => {
      totalRisk += 2; // Manual changes carry inherent risk
    });
    
    const averageRisk = totalFixes > 0 ? totalRisk / totalFixes : 0;
    
    return {
      level: averageRisk <= 1.5 ? 'low' : averageRisk <= 3 ? 'medium' : 'high',
      score: Math.round(averageRisk * 10) / 10,
      totalFixes,
      autoFixable: plan.fixes.length,
      requiresReview: plan.suggestions.length,
      recommendation: this.getRecommendation(averageRisk, totalFixes)
    };
  }

  getRecommendation(riskScore, totalFixes) {
    if (totalFixes === 0) return 'No fixes needed';
    if (riskScore <= 1.5) return 'Safe to apply automatic fixes';
    if (riskScore <= 3) return 'Review automatic fixes before applying';
    return 'Manual review required for all fixes';
  }

  async applyAutomaticFixes(filePath, content, plan) {
    const appliedFixes = [];
    
    if (plan.riskAssessment.level === 'high') {
      logger.warn(`⚠️ High risk remediation plan for ${filePath} - skipping automatic fixes`);
      return appliedFixes;
    }
    
    // Create backup if enabled
    if (this.options.backupOriginal) {
      await this.createBackup(filePath, content);
    }
    
    let modifiedContent = content;
    
    // Apply fixes in reverse order to maintain line numbers
    const sortedFixes = plan.fixes.sort((a, b) => 
      (b.location?.line || 0) - (a.location?.line || 0)
    );
    
    for (const fix of sortedFixes) {
      if (fix.autoFixable && this.isFixSafe(fix)) {
        try {
          modifiedContent = this.applyFix(modifiedContent, fix);
          appliedFixes.push(fix);
          logger.info(`✅ Applied fix for ${fix.rule} at line ${fix.location?.line}`);
        } catch (error) {
          logger.error(`❌ Failed to apply fix for ${fix.rule}:`, error.message);
        }
      }
    }
    
    // Write modified content back to file
    if (appliedFixes.length > 0) {
      await fs.writeFile(filePath, modifiedContent);
      logger.info(`✅ Applied ${appliedFixes.length} automatic fixes to ${filePath}`);
      
      // Record fix history
      this.fixHistory.push({
        file: filePath,
        timestamp: new Date().toISOString(),
        appliedFixes: appliedFixes.length,
        fixes: appliedFixes.map(f => ({ rule: f.rule, severity: f.severity }))
      });
    }
    
    return appliedFixes;
  }

  applyFix(content, fix) {
    let modifiedContent = content;
    
    // Apply changes in reverse order to maintain positions
    const sortedChanges = fix.changes.sort((a, b) => b.line - a.line);
    
    for (const change of sortedChanges) {
      if (change.type === 'replace') {
        modifiedContent = modifiedContent.replace(change.original, change.replacement);
      }
    }
    
    return modifiedContent;
  }

  async createBackup(filePath, content) {
    const backupPath = `${filePath}.backup.${Date.now()}`;
    await fs.writeFile(backupPath, content);
    logger.info(`📦 Created backup: ${backupPath}`);
  }

  async generateAISuggestion(finding, content, context = {}) {
    // Placeholder for AI-powered suggestion generation
    // In production, integrate with OpenAI API or other AI services
    
    const prompt = this.buildAIPrompt(finding, content, context);
    
    try {
      // Simulated AI response
      const suggestion = {
        id: `ai-suggestion-${finding.id}`,
        rule: finding.rule,
        type: 'ai-generated',
        description: `AI-suggested fix for ${finding.rule}`,
        recommendations: [
          {
            priority: 'medium',
            action: `Review and fix ${finding.rule}`,
            details: `Consider implementing proper security measures for this ${finding.rule} vulnerability`,
            effort: 'medium',
            impact: this.estimateImpact(finding.severity)
          }
        ],
        confidence: 0.7,
        reasoning: `Based on the code analysis, this appears to be a ${finding.rule} issue that requires attention`,
        examples: []
      };
      
      return suggestion;
    } catch (error) {
      logger.error('AI suggestion generation failed:', error.message);
      return this.createFallbackSuggestion(finding);
    }
  }

  buildAIPrompt(finding, content, context) {
    return `
You are a senior security engineer reviewing code for vulnerabilities.

Issue: ${finding.rule} (${finding.severity} severity)
Location: Line ${finding.location?.line}
Code context:
\`\`\`
${this.extractContext(content, finding.location || {}).current}
\`\`\`

Please provide:
1. A clear explanation of the security issue
2. Specific remediation steps
3. Code example showing the fix
4. Additional security best practices

Focus on practical, implementable solutions.
    `.trim();
  }

  createFallbackSuggestion(finding) {
    return {
      id: `fallback-suggestion-${finding.id}`,
      rule: finding.rule,
      type: 'fallback',
      description: `Manual review required for ${finding.rule}`,
      recommendations: [
        {
          priority: 'medium',
          action: 'Manual security review',
          details: `This ${finding.rule} issue requires manual review and remediation`,
          effort: 'high',
          impact: this.estimateImpact(finding.severity)
        }
      ],
      confidence: 0.5
    };
  }

  async generateSuggestions(plan) {
    const suggestions = [];
    
    for (const fix of plan.fixes) {
      if (!fix.autoFixable || !this.isFixSafe(fix)) {
        suggestions.push(await this.convertFixToSuggestion(fix));
      }
    }
    
    suggestions.push(...plan.suggestions);
    
    return suggestions;
  }

  async convertFixToSuggestion(fix) {
    return {
      id: fix.id.replace('fix-', 'suggestion-'),
      rule: fix.rule,
      severity: fix.severity,
      description: fix.description,
      location: fix.location,
      recommendations: [
        {
          priority: fix.severity === 'critical' ? 'critical' : 'high',
          action: fix.description,
          details: `Manual review required: ${fix.riskLevel} risk level`,
          effort: this.estimateEffort({ riskLevel: fix.riskLevel, type: 'security' }),
          impact: this.estimateImpact(fix.severity)
        }
      ],
      changes: fix.changes
    };
  }

  async generateRemediationReport(results, outputPath) {
    try {
      const report = {
        metadata: {
          timestamp: new Date().toISOString(),
          engine: 'Remediation Engine',
          version: '1.0.0'
        },
        summary: this.generateRemediationSummary(results),
        results: results,
        history: this.fixHistory.slice(-100), // Last 100 fixes
        recommendations: this.generateGlobalRecommendations(results)
      };
      
      await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
      logger.info(`✅ Remediation report generated: ${outputPath}`);
      
      return report;
    } catch (error) {
      logger.error('Failed to generate remediation report:', error.message);
      throw error;
    }
  }

  generateRemediationSummary(results) {
    let totalFiles = 0;
    let totalFixes = 0;
    let totalSuggestions = 0;
    let appliedFixes = 0;
    
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    results.forEach(result => {
      totalFiles++;
      if (result.plan) {
        totalFixes += result.plan.fixes.length;
        totalSuggestions += result.plan.suggestions.length;
        
        result.plan.fixes.forEach(fix => {
          severityCounts[fix.severity] = (severityCounts[fix.severity] || 0) + 1;
        });
      }
      
      if (result.appliedFixes) {
        appliedFixes += result.appliedFixes.length;
      }
    });
    
    return {
      totalFiles,
      totalIssues: totalFixes + totalSuggestions,
      autoFixable: totalFixes,
      manualReview: totalSuggestions,
      appliedFixes,
      pendingFixes: totalFixes - appliedFixes,
      bySeverity: severityCounts,
      remediationRate: totalFixes > 0 ? Math.round((appliedFixes / totalFixes) * 100) : 0
    };
  }

  generateGlobalRecommendations(results) {
    const recommendations = [];
    
    const summary = this.generateRemediationSummary(results);
    
    if (summary.bySeverity.critical > 0) {
      recommendations.push({
        priority: 'critical',
        action: 'Address critical security vulnerabilities immediately',
        details: `${summary.bySeverity.critical} critical issues require immediate attention`
      });
    }
    
    if (summary.remediationRate < 50) {
      recommendations.push({
        priority: 'high',
        action: 'Enable automatic fixes for low-risk issues',
        details: 'Consider enabling auto-fixing for low-risk security issues to improve remediation rate'
      });
    }
    
    if (summary.manualReview > summary.autoFixable) {
      recommendations.push({
        priority: 'medium',
        action: 'Implement security training for development team',
        details: 'High number of manual review items suggests need for security awareness training'
      });
    }
    
    return recommendations;
  }

  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async cleanup() {
    try {
      logger.info('🧹 Cleaning up Remediation Engine...');
      this.initialized = false;
      this.remediationRules.clear();
      this.suggestions.clear();
      logger.info('✅ Remediation Engine cleanup completed');
    } catch (error) {
      logger.error('❌ Remediation Engine cleanup failed:', error.message);
    }
  }

  isReady() {
    return this.initialized;
  }

  getFixHistory() {
    return [...this.fixHistory];
  }

  getRemediationStats() {
    return {
      totalRules: this.remediationRules.size,
      fixHistory: this.fixHistory.length,
      initialized: this.initialized
    };
  }
}

module.exports = RemediationEngine;