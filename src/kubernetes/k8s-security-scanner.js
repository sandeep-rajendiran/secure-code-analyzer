const k8s = require('@kubernetes/client-node');
const yaml = require('js-yaml');
const fs = require('fs').promises;
const path = require('path');
const logger = require('../utils/logger');

class KubernetesSecurityScanner {
  constructor(options = {}) {
    this.kubeConfig = new k8s.KubeConfig();
    this.options = {
      namespace: options.namespace || 'secure-code-analyzer',
      scanDepth: options.scanDepth || 'comprehensive',
      outputFormat: options.outputFormat || 'json',
      ...options
    };
    
    this.securityRules = new Map();
    this.findings = [];
    this.metrics = new Map();
    
    this.initializeKubeConfig();
    this.initializeSecurityRules();
  }

  initializeKubeConfig() {
    try {
      // Try to load from cluster (in-cluster configuration)
      this.kubeConfig.loadFromCluster();
      logger.info('✅ Loaded in-cluster Kubernetes configuration');
    } catch (error) {
      try {
        // Fallback to local kubeconfig
        this.kubeConfig.loadFromDefault();
        logger.info('✅ Loaded local Kubernetes configuration');
      } catch (fallbackError) {
        logger.error('❌ Failed to load Kubernetes configuration:', fallbackError.message);
        throw fallbackError;
      }
    }
    
    this.coreV1Api = this.kubeConfig.makeApiClient(k8s.CoreV1Api);
    this.appsV1Api = this.kubeConfig.makeApiClient(k8s.AppsV1Api);
    this.networkingV1Api = this.kubeConfig.makeApiClient(k8s.NetworkingV1Api);
    this.rbacV1Api = this.kubeConfig.makeApiClient(k8s.RbacAuthorizationV1Api);
    this.policyV1Api = this.kubeConfig.makeApiClient(k8s.PolicyV1Api);
  }

  initializeSecurityRules() {
    this.securityRules.set('privileged-containers', {
      severity: 'critical',
      description: 'Container running with privileged access',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => 
            container.securityContext?.privileged === true
          );
        }
        return false;
      }
    });

    this.securityRules.set('root-user', {
      severity: 'high',
      description: 'Container running as root user (UID 0)',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => 
            container.securityContext?.runAsUser === 0 ||
            (!container.securityContext?.runAsUser && !container.securityContext?.runAsNonRoot)
          );
        }
        return false;
      }
    });

    this.securityRules.set('writable-root-filesystem', {
      severity: 'medium',
      description: 'Container with writable root filesystem',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => 
            container.securityContext?.readOnlyRootFilesystem !== true
          );
        }
        return false;
      }
    });

    this.securityRules.set('missing-security-context', {
      severity: 'medium',
      description: 'Missing security context configuration',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => !container.securityContext);
        }
        return false;
      }
    });

    this.securityRules.set('dangerous-capabilities', {
      severity: 'high',
      description: 'Container with dangerous Linux capabilities',
      check: (resource) => {
        const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_TIME', 'SYS_MODULE'];
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => {
            const addedCaps = container.securityContext?.capabilities?.add || [];
            return addedCaps.some(cap => dangerousCaps.includes(cap));
          });
        }
        return false;
      }
    });

    this.securityRules.set('host-network', {
      severity: 'critical',
      description: 'Pod using host network',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const spec = resource.kind === 'Deployment' ? resource.spec?.template?.spec : resource.spec;
          return spec?.hostNetwork === true;
        }
        return false;
      }
    });

    this.securityRules.set('host-pid', {
      severity: 'high',
      description: 'Pod using host PID namespace',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const spec = resource.kind === 'Deployment' ? resource.spec?.template?.spec : resource.spec;
          return spec?.hostPID === true;
        }
        return false;
      }
    });

    this.securityRules.set('host-ipc', {
      severity: 'high',
      description: 'Pod using host IPC namespace',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const spec = resource.kind === 'Deployment' ? resource.spec?.template?.spec : resource.spec;
          return spec?.hostIPC === true;
        }
        return false;
      }
    });

    this.securityRules.set('no-resource-limits', {
      severity: 'medium',
      description: 'Container without resource limits',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const containers = this.extractContainers(resource);
          return containers.some(container => 
            !container.resources?.limits?.cpu || !container.resources?.limits?.memory
          );
        }
        return false;
      }
    });

    this.securityRules.set('default-service-account', {
      severity: 'low',
      description: 'Using default service account',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const spec = resource.kind === 'Deployment' ? resource.spec?.template?.spec : resource.spec;
          return !spec?.serviceAccountName || spec.serviceAccountName === 'default';
        }
        return false;
      }
    });

    this.securityRules.set('automount-service-account', {
      severity: 'medium',
      description: 'Service account token automatically mounted',
      check: (resource) => {
        if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
          const spec = resource.kind === 'Deployment' ? resource.spec?.template?.spec : resource.spec;
          return spec?.automountServiceAccountToken !== false;
        }
        return false;
      }
    });

    this.securityRules.set('insecure-port', {
      severity: 'medium',
      description: 'Service exposing insecure ports',
      check: (resource) => {
        if (resource.kind === 'Service') {
          const insecurePorts = [22, 23, 80, 135, 139, 445, 1433, 1521, 3306, 5432, 6379, 9200, 27017];
          return resource.spec?.ports?.some(port => 
            insecurePorts.includes(port.port) && resource.spec?.type === 'LoadBalancer'
          );
        }
        return false;
      }
    });

    this.securityRules.set('weak-rbac', {
      severity: 'high',
      description: 'Overly permissive RBAC configuration',
      check: (resource) => {
        if (resource.kind === 'ClusterRole' || resource.kind === 'Role') {
          const dangerousVerbs = ['*', 'create', 'update', 'patch', 'delete'];
          const dangerousResources = ['*', 'secrets', 'pods/exec', 'pods/portforward'];
          
          return resource.rules?.some(rule => 
            (rule.verbs?.includes('*') || dangerousVerbs.some(verb => rule.verbs?.includes(verb))) &&
            (rule.resources?.includes('*') || dangerousResources.some(res => rule.resources?.includes(res)))
          );
        }
        return false;
      }
    });

    this.securityRules.set('missing-network-policy', {
      severity: 'medium',
      description: 'Namespace without network policy',
      check: (resource, context) => {
        if (resource.kind === 'Namespace') {
          return !context.networkPolicies?.some(np => 
            np.metadata?.namespace === resource.metadata?.name
          );
        }
        return false;
      }
    });

    this.securityRules.set('unencrypted-secret', {
      severity: 'high',
      description: 'Secret with unencrypted data',
      check: (resource) => {
        if (resource.kind === 'Secret') {
          // Check for common patterns that indicate plaintext secrets
          const suspiciousPatterns = [
            /password.*[123456789]/i,
            /secret.*[123456789]/i,
            /token.*[abc123]/i,
            /key.*[123]/i
          ];
          
          const dataValues = Object.values(resource.data || {}).concat(
            Object.values(resource.stringData || {})
          );
          
          return dataValues.some(value => {
            const decoded = Buffer.from(value, 'base64').toString('utf8');
            return suspiciousPatterns.some(pattern => pattern.test(decoded));
          });
        }
        return false;
      }
    });
  }

  extractContainers(resource) {
    if (resource.kind === 'Pod') {
      return resource.spec?.containers || [];
    } else if (resource.kind === 'Deployment') {
      return resource.spec?.template?.spec?.containers || [];
    }
    return [];
  }

  async scanCluster() {
    try {
      logger.info('🔍 Starting Kubernetes cluster security scan...');
      
      this.findings = [];
      this.metrics.clear();
      
      const startTime = Date.now();
      
      // Gather all resources
      const resources = await this.gatherResources();
      const context = await this.buildContext(resources);
      
      // Scan each resource
      for (const resource of resources) {
        await this.scanResource(resource, context);
      }
      
      // Additional cluster-wide scans
      await this.scanClusterConfiguration(context);
      
      const scanTime = Date.now() - startTime;
      this.metrics.set('scan_duration_ms', scanTime);
      this.metrics.set('resources_scanned', resources.length);
      this.metrics.set('total_findings', this.findings.length);
      
      // Calculate risk score
      const riskScore = this.calculateRiskScore();
      this.metrics.set('risk_score', riskScore);
      
      logger.info(`✅ Kubernetes security scan completed in ${scanTime}ms`);
      logger.info(`📊 Scanned ${resources.length} resources, found ${this.findings.length} security issues`);
      
      return {
        findings: this.findings,
        metrics: Object.fromEntries(this.metrics),
        summary: this.generateSummary(),
        riskScore
      };
      
    } catch (error) {
      logger.error('❌ Kubernetes security scan failed:', error.message);
      throw error;
    }
  }

  async gatherResources() {
    const resources = [];
    
    try {
      // Gather Pods
      const pods = await this.coreV1Api.listPodForAllNamespaces();
      resources.push(...pods.body.items.map(item => ({...item, kind: 'Pod'})));
      
      // Gather Deployments
      const deployments = await this.appsV1Api.listDeploymentForAllNamespaces();
      resources.push(...deployments.body.items.map(item => ({...item, kind: 'Deployment'})));
      
      // Gather Services
      const services = await this.coreV1Api.listServiceForAllNamespaces();
      resources.push(...services.body.items.map(item => ({...item, kind: 'Service'})));
      
      // Gather Secrets
      const secrets = await this.coreV1Api.listSecretForAllNamespaces();
      resources.push(...secrets.body.items.map(item => ({...item, kind: 'Secret'})));
      
      // Gather ConfigMaps
      const configMaps = await this.coreV1Api.listConfigMapForAllNamespaces();
      resources.push(...configMaps.body.items.map(item => ({...item, kind: 'ConfigMap'})));
      
      // Gather Namespaces
      const namespaces = await this.coreV1Api.listNamespace();
      resources.push(...namespaces.body.items.map(item => ({...item, kind: 'Namespace'})));
      
      // Gather RBAC resources
      try {
        const clusterRoles = await this.rbacV1Api.listClusterRole();
        resources.push(...clusterRoles.body.items.map(item => ({...item, kind: 'ClusterRole'})));
        
        const roles = await this.rbacV1Api.listRoleForAllNamespaces();
        resources.push(...roles.body.items.map(item => ({...item, kind: 'Role'})));
      } catch (rbacError) {
        logger.warn('Warning: Could not gather RBAC resources:', rbacError.message);
      }
      
      // Gather Network Policies
      try {
        const networkPolicies = await this.networkingV1Api.listNetworkPolicyForAllNamespaces();
        resources.push(...networkPolicies.body.items.map(item => ({...item, kind: 'NetworkPolicy'})));
      } catch (netpolError) {
        logger.warn('Warning: Could not gather NetworkPolicies:', netpolError.message);
      }
      
      return resources;
    } catch (error) {
      logger.error('Error gathering Kubernetes resources:', error.message);
      throw error;
    }
  }

  async buildContext(resources) {
    const context = {
      namespaces: resources.filter(r => r.kind === 'Namespace'),
      networkPolicies: resources.filter(r => r.kind === 'NetworkPolicy'),
      secrets: resources.filter(r => r.kind === 'Secret'),
      services: resources.filter(r => r.kind === 'Service'),
      pods: resources.filter(r => r.kind === 'Pod'),
      deployments: resources.filter(r => r.kind === 'Deployment')
    };
    
    return context;
  }

  async scanResource(resource, context) {
    for (const [ruleName, rule] of this.securityRules) {
      try {
        if (rule.check(resource, context)) {
          this.findings.push({
            id: `${resource.kind}-${resource.metadata?.name}-${ruleName}`,
            rule: ruleName,
            severity: rule.severity,
            description: rule.description,
            resource: {
              kind: resource.kind,
              name: resource.metadata?.name,
              namespace: resource.metadata?.namespace
            },
            timestamp: new Date().toISOString(),
            details: this.generateFindingDetails(resource, rule)
          });
        }
      } catch (error) {
        logger.warn(`Warning: Rule ${ruleName} failed for resource ${resource.kind}/${resource.metadata?.name}:`, error.message);
      }
    }
  }

  async scanClusterConfiguration(context) {
    // Scan for cluster-wide security issues
    
    // Check for default deny-all network policy
    const hasDefaultDenyPolicy = context.networkPolicies.some(np => 
      np.spec?.podSelector && Object.keys(np.spec.podSelector).length === 0 &&
      (!np.spec?.ingress || np.spec.ingress.length === 0) &&
      np.spec?.policyTypes?.includes('Ingress')
    );
    
    if (!hasDefaultDenyPolicy) {
      this.findings.push({
        id: 'cluster-missing-default-deny-network-policy',
        rule: 'missing-default-deny-network-policy',
        severity: 'medium',
        description: 'No default deny-all network policy found',
        resource: { kind: 'Cluster', name: 'cluster-wide' },
        timestamp: new Date().toISOString(),
        details: 'Consider implementing a default deny-all network policy for improved security'
      });
    }
    
    // Check for excessive service accounts
    const serviceAccounts = new Set();
    context.pods.forEach(pod => {
      if (pod.spec?.serviceAccountName && pod.spec.serviceAccountName !== 'default') {
        serviceAccounts.add(`${pod.metadata?.namespace}/${pod.spec.serviceAccountName}`);
      }
    });
    
    if (serviceAccounts.size > 50) {
      this.findings.push({
        id: 'cluster-excessive-service-accounts',
        rule: 'excessive-service-accounts',
        severity: 'low',
        description: `Large number of service accounts (${serviceAccounts.size})`,
        resource: { kind: 'Cluster', name: 'cluster-wide' },
        timestamp: new Date().toISOString(),
        details: 'Review service account usage and consolidate where possible'
      });
    }
  }

  generateFindingDetails(resource, rule) {
    const details = {
      resourceDetails: {
        apiVersion: resource.apiVersion,
        metadata: {
          name: resource.metadata?.name,
          namespace: resource.metadata?.namespace,
          labels: resource.metadata?.labels,
          annotations: resource.metadata?.annotations
        }
      }
    };
    
    // Add specific details based on resource type
    if (resource.kind === 'Pod' || resource.kind === 'Deployment') {
      const containers = this.extractContainers(resource);
      details.containers = containers.map(container => ({
        name: container.name,
        image: container.image,
        securityContext: container.securityContext,
        resources: container.resources
      }));
    } else if (resource.kind === 'Service') {
      details.serviceDetails = {
        type: resource.spec?.type,
        ports: resource.spec?.ports,
        selector: resource.spec?.selector
      };
    } else if (resource.kind === 'Secret') {
      details.secretDetails = {
        type: resource.type,
        dataKeys: Object.keys(resource.data || {})
      };
    }
    
    return details;
  }

  calculateRiskScore() {
    let score = 100;
    
    this.findings.forEach(finding => {
      switch (finding.severity) {
        case 'critical':
          score -= 20;
          break;
        case 'high':
          score -= 10;
          break;
        case 'medium':
          score -= 5;
          break;
        case 'low':
          score -= 2;
          break;
      }
    });
    
    return Math.max(0, score);
  }

  generateSummary() {
    const summary = {
      totalFindings: this.findings.length,
      bySeverity: {
        critical: this.findings.filter(f => f.severity === 'critical').length,
        high: this.findings.filter(f => f.severity === 'high').length,
        medium: this.findings.filter(f => f.severity === 'medium').length,
        low: this.findings.filter(f => f.severity === 'low').length
      },
      byResourceType: {},
      topIssues: {}
    };
    
    // Group by resource type
    this.findings.forEach(finding => {
      const resourceType = finding.resource.kind;
      summary.byResourceType[resourceType] = (summary.byResourceType[resourceType] || 0) + 1;
    });
    
    // Count top issues
    this.findings.forEach(finding => {
      summary.topIssues[finding.rule] = (summary.topIssues[finding.rule] || 0) + 1;
    });
    
    // Sort top issues
    summary.topIssues = Object.entries(summary.topIssues)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .reduce((obj, [key, value]) => ({ ...obj, [key]: value }), {});
    
    return summary;
  }

  async generateReport(outputPath) {
    try {
      const report = {
        metadata: {
          timestamp: new Date().toISOString(),
          scanner: 'Kubernetes Security Scanner',
          version: '1.0.0',
          cluster: await this.getClusterInfo()
        },
        findings: this.findings,
        metrics: Object.fromEntries(this.metrics),
        summary: this.generateSummary(),
        recommendations: this.generateRecommendations()
      };
      
      let content;
      
      if (this.options.outputFormat === 'yaml') {
        content = yaml.dump(report);
      } else if (this.options.outputFormat === 'html') {
        content = this.generateHTMLReport(report);
      } else {
        content = JSON.stringify(report, null, 2);
      }
      
      await fs.writeFile(outputPath, content);
      logger.info(`✅ Kubernetes security report generated: ${outputPath}`);
      
      return outputPath;
    } catch (error) {
      logger.error('Failed to generate Kubernetes security report:', error.message);
      throw error;
    }
  }

  async getClusterInfo() {
    try {
      const version = await this.coreV1Api.getAPIVersions();
      const nodes = await this.coreV1Api.listNode();
      
      return {
        version: version.body.versions?.[0] || 'unknown',
        nodeCount: nodes.body.items?.length || 0,
        masterVersion: nodes.body.items?.[0]?.status?.nodeInfo?.kubeletVersion || 'unknown'
      };
    } catch (error) {
      return { version: 'unknown', nodeCount: 0, masterVersion: 'unknown' };
    }
  }

  generateRecommendations() {
    const recommendations = [];
    
    const criticalCount = this.findings.filter(f => f.severity === 'critical').length;
    const highCount = this.findings.filter(f => f.severity === 'high').length;
    
    if (criticalCount > 0) {
      recommendations.push({
        priority: 'critical',
        action: 'Immediately address critical security findings',
        description: `${criticalCount} critical security issues require immediate attention`
      });
    }
    
    if (highCount > 5) {
      recommendations.push({
        priority: 'high',
        action: 'Implement Pod Security Standards',
        description: 'Consider implementing Pod Security Standards to prevent common security misconfigurations'
      });
    }
    
    const networkPolicyFindings = this.findings.filter(f => f.rule.includes('network')).length;
    if (networkPolicyFindings > 0) {
      recommendations.push({
        priority: 'medium',
        action: 'Implement network segmentation',
        description: 'Use NetworkPolicies to implement proper network segmentation'
      });
    }
    
    const rbacFindings = this.findings.filter(f => f.rule.includes('rbac') || f.rule.includes('service-account')).length;
    if (rbacFindings > 0) {
      recommendations.push({
        priority: 'medium',
        action: 'Review RBAC configuration',
        description: 'Implement least-privilege RBAC policies and avoid using default service accounts'
      });
    }
    
    return recommendations;
  }

  generateHTMLReport(report) {
    const { summary } = report;
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Kubernetes Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: #326ce5; color: white; border-radius: 5px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #333; }
        .severity-critical { color: #dc3545; } .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; } .severity-low { color: #28a745; }
        .findings-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .findings-table th, .findings-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .findings-table th { background: #f8f9fa; }
        .chart { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Kubernetes Security Scan Report</h1>
            <p>Cluster Security Assessment</p>
            <p>Generated: ${report.metadata.timestamp}</p>
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value">${summary.totalFindings}</div>
                <div>Total Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-critical">${summary.bySeverity.critical}</div>
                <div>Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-high">${summary.bySeverity.high}</div>
                <div>High</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-medium">${summary.bySeverity.medium}</div>
                <div>Medium</div>
            </div>
            <div class="metric-card">
                <div class="metric-value severity-low">${summary.bySeverity.low}</div>
                <div>Low</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${report.metrics.risk_score || 0}</div>
                <div>Security Score</div>
            </div>
        </div>

        <h3>📊 Findings by Resource Type</h3>
        <table class="findings-table">
            <thead>
                <tr><th>Resource Type</th><th>Issues Found</th></tr>
            </thead>
            <tbody>
                ${Object.entries(summary.byResourceType).map(([type, count]) => 
                    `<tr><td>${type}</td><td>${count}</td></tr>`
                ).join('')}
            </tbody>
        </table>

        <h3>🔍 Top Security Issues</h3>
        <table class="findings-table">
            <thead>
                <tr><th>Security Rule</th><th>Occurrences</th></tr>
            </thead>
            <tbody>
                ${Object.entries(summary.topIssues).map(([rule, count]) => 
                    `<tr><td>${rule.replace(/-/g, ' ')}</td><td>${count}</td></tr>`
                ).join('')}
            </tbody>
        </table>

        <h3>💡 Recommendations</h3>
        <ul>
            ${report.recommendations.map(rec => 
                `<li><strong>${rec.action}:</strong> ${rec.description}</li>`
            ).join('')}
        </ul>

        <div style="text-align: center; margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
            <p>Generated by Secure Code Analyzer - Kubernetes Security Scanner v1.0.0</p>
        </div>
    </div>
</body>
</html>
    `;
  }
}

module.exports = KubernetesSecurityScanner;