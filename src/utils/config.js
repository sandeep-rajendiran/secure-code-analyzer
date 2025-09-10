require('dotenv').config();

const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || 'info',
  
  database: {
    host: process.env.DATABASE_HOST || 'localhost',
    port: process.env.DATABASE_PORT || 5432,
    name: process.env.DATABASE_NAME || 'secure_code_analyzer',
    user: process.env.DATABASE_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || 'password'
  },
  
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379
  },
  
  sonarqube: {
    url: process.env.SONARQUBE_URL || 'http://localhost:9000',
    token: process.env.SONARQUBE_TOKEN,
    organization: process.env.SONARQUBE_ORGANIZATION,
    qualityGate: process.env.SONARQUBE_QUALITY_GATE || 'Sonar way'
  },
  
  jenkins: {
    url: process.env.JENKINS_URL || 'http://localhost:8080',
    token: process.env.JENKINS_TOKEN
  },
  
  security: {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    encryptionKey: process.env.ENCRYPTION_KEY
  }
};

module.exports = config;