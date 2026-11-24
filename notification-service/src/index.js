require('dotenv').config();
const emailConsumer = require('./kafka/consumer/email.consumer');
const emailService = require('./services/email.service');
const logger = require('./config/logger');

async function startNotificationService() {
     try {
          logger.info('Starting Notification Service...');

          const requiredEnvVars = ['SMTP_USER', 'SMTP_PASS', 'MAIL_SEND', 'KAFKA_BROKER'];
          const missing = requiredEnvVars.filter(varName => !process.env[varName]);

          if (missing.length > 0) {
               throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
          }

          // Best-effort SMTP handshake check before accepting Kafka messages
          await emailService.verifyConnection();

          await emailConsumer.start();

          logger.info('✅ Notification Service started successfully');
          logger.info('Service is ready to process notifications');

     } catch (error) {
          logger.error('Failed to start Notification Service', {
               error: error.message,
               stack: error.stack
          });
          process.exit(1);
     }
}

process.on('unhandledRejection', (reason, promise) => {
     logger.error('Unhandled Rejection', { reason, promise });
});

process.on('uncaughtException', (error) => {
     logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
     process.exit(1);
});

startNotificationService();
