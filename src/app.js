#!/usr/bin/env node

/**
 * Secure Code Analyzer - Enterprise DevSecOps Integration
 * Main application entry point
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');

// Import modules
const logger = require('./utils/logger');
const config = require('./utils/config');
const { errorHandler, notFoundHandler } = require('./utils/middleware');
const SecurityAnalyzer = require('./analyzers/security-analyzer');
const StaticAnalyzer = require('./analyzers/static-analyzer');
const DynamicAnalyzer = require('./analyzers/dynamic-analyzer');
const RemediationEngine = require('./remediation/remediation-engine');

// Import routes
const analysisRoutes = require('./api/analysis-routes');
const pipelineRoutes = require('./api/pipeline-routes');
const reportRoutes = require('./api/report-routes');
const dashboardRoutes = require('./api/dashboard-routes');

class SecureCodeAnalyzerApp {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.io = socketIo(this.server, {
      cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3001",
        methods: ["GET", "POST"]
      }
    });
    
    this.securityAnalyzer = new SecurityAnalyzer();
    this.staticAnalyzer = new StaticAnalyzer();
    this.dynamicAnalyzer = new DynamicAnalyzer();
    this.remediationEngine = new RemediationEngine();
    
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeErrorHandling();
    this.initializeWebSocket();
  }

  initializeMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
          scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration
    this.app.use(cors({
      origin: process.env.NODE_ENV === 'production' 
        ? process.env.FRONTEND_URL 
        : ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true
    }));

    // Logging
    this.app.use(morgan('combined', { 
      stream: { write: message => logger.info(message.trim()) }
    }));

    // Body parsing
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Static files
    this.app.use('/static', express.static(path.join(__dirname, '../dashboard/public')));

    // Request logging
    this.app.use((req, res, next) => {
      logger.info(`${req.method} ${req.path} - ${req.ip}`);
      next();
    });
  }

  initializeRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        uptime: process.uptime(),
        services: {
          staticAnalyzer: this.staticAnalyzer.isReady(),
          dynamicAnalyzer: this.dynamicAnalyzer.isReady(),
          remediationEngine: this.remediationEngine.isReady()
        }
      });
    });

    // API routes
    this.app.use('/api/v1/analysis', analysisRoutes);
    this.app.use('/api/v1/pipeline', pipelineRoutes);
    this.app.use('/api/v1/reports', reportRoutes);
    this.app.use('/api/v1/dashboard', dashboardRoutes);

    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        name: 'Secure Code Analyzer',
        version: '1.0.0',
        description: 'Enterprise DevSecOps Integration Platform',
        features: [
          'Static Code Analysis',
          'Dynamic Security Testing',
          'CI/CD Pipeline Integration',
          'Automated Remediation',
          'Real-time Monitoring',
          'Compliance Reporting'
        ],
        endpoints: {
          health: '/health',
          analysis: '/api/v1/analysis',
          pipeline: '/api/v1/pipeline',
          reports: '/api/v1/reports',
          dashboard: '/api/v1/dashboard',
          docs: '/docs'
        }
      });
    });

    // Documentation
    this.app.get('/docs', (req, res) => {
      res.sendFile(path.join(__dirname, '../docs/api-docs.html'));
    });
  }

  initializeErrorHandling() {
    this.app.use(notFoundHandler);
    this.app.use(errorHandler);
  }

  initializeWebSocket() {
    this.io.on('connection', (socket) => {
      logger.info(`WebSocket client connected: ${socket.id}`);

      socket.on('subscribe-analysis', (analysisId) => {
        socket.join(`analysis-${analysisId}`);
        logger.info(`Client ${socket.id} subscribed to analysis ${analysisId}`);
      });

      socket.on('subscribe-pipeline', (pipelineId) => {
        socket.join(`pipeline-${pipelineId}`);
        logger.info(`Client ${socket.id} subscribed to pipeline ${pipelineId}`);
      });

      socket.on('disconnect', () => {
        logger.info(`WebSocket client disconnected: ${socket.id}`);
      });
    });

    // Make io available to other modules
    this.app.set('io', this.io);
  }

  async start() {
    try {
      // Initialize analyzers
      await this.securityAnalyzer.initialize();
      await this.staticAnalyzer.initialize();
      await this.dynamicAnalyzer.initialize();
      await this.remediationEngine.initialize();

      const port = config.port || 3000;
      
      this.server.listen(port, () => {
        logger.info(`🚀 Secure Code Analyzer started on port ${port}`);
        logger.info(`📊 Dashboard: http://localhost:${port}/dashboard`);
        logger.info(`📖 API Docs: http://localhost:${port}/docs`);
        logger.info(`🏥 Health Check: http://localhost:${port}/health`);
        
        // Display startup banner
        this.displayBanner();
      });

      // Graceful shutdown
      process.on('SIGTERM', () => this.gracefulShutdown());
      process.on('SIGINT', () => this.gracefulShutdown());

    } catch (error) {
      logger.error('Failed to start application:', error);
      process.exit(1);
    }
  }

  async gracefulShutdown() {
    logger.info('🛑 Shutting down gracefully...');
    
    this.server.close(async () => {
      try {
        await this.securityAnalyzer.cleanup();
        await this.staticAnalyzer.cleanup();
        await this.dynamicAnalyzer.cleanup();
        await this.remediationEngine.cleanup();
        
        logger.info('✅ Cleanup completed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during cleanup:', error);
        process.exit(1);
      }
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
      logger.error('💥 Forced shutdown');
      process.exit(1);
    }, 30000);
  }

  displayBanner() {
    const banner = `
╔══════════════════════════════════════════════════════════════╗
║                 SECURE CODE ANALYZER v1.0.0                 ║
║              Enterprise DevSecOps Integration                ║
╠══════════════════════════════════════════════════════════════╣
║  🛡️  Static Code Analysis      📊  Real-time Dashboard     ║
║  🔍  Dynamic Security Testing   🚀  CI/CD Integration       ║
║  🤖  Automated Remediation      📈  Compliance Reporting    ║
║  🔧  Jenkins Integration        ☸️   Kubernetes Ready       ║
╚══════════════════════════════════════════════════════════════╝
`;
    console.log(banner);
  }
}

// Error handling for unhandled promises
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the application
if (require.main === module) {
  const app = new SecureCodeAnalyzerApp();
  app.start();
}

module.exports = SecureCodeAnalyzerApp;