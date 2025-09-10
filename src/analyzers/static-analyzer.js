const logger = require('../utils/logger');

class StaticAnalyzer {
  constructor() {
    this.initialized = false;
  }

  async initialize() {
    logger.info('Static Analyzer initializing...');
    this.initialized = true;
    return true;
  }

  isReady() {
    return this.initialized;
  }

  async cleanup() {
    logger.info('Static Analyzer cleanup...');
    this.initialized = false;
  }
}

module.exports = StaticAnalyzer;