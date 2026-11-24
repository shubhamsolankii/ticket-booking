const nodemailer = require('nodemailer');
const logger = require('../config/logger');
const { config } = require('../config');
const { getOtpTemplate, getWelcomeTemplate, getTicketConfirmationTemplate } = require('../templates');

class EmailService {
     constructor() {
          this.from = config.MAIL_SEND;
          this.maxRetries = 3;

          this.transporter = nodemailer.createTransport({
               host: config.SMTP_HOST,
               port: config.SMTP_PORT,
               secure: config.SMTP_PORT === 465,
               auth: {
                    user: config.SMTP_USER,
                    pass: config.SMTP_PASS,
               },
          });
     }

     /**
      * Verify SMTP connection on startup (best-effort, logs warning on failure).
      */
     async verifyConnection() {
          try {
               await this.transporter.verify();
               logger.info('SMTP connection verified successfully');
          } catch (error) {
               logger.warn('SMTP connection verification failed — emails may fail at send time', {
                    error: error.message,
               });
          }
     }

     async sendWithRetry(msg, retries = 0) {
          try {
               const info = await this.transporter.sendMail({
                    from: msg.from,
                    to: msg.to,
                    subject: msg.subject,
                    html: msg.html,
               });
               logger.info(`Email sent successfully to ${msg.to}`, {
                    subject: msg.subject,
                    messageId: info.messageId,
                    attempt: retries + 1,
               });
               return { success: true, messageId: info.messageId };
          } catch (error) {
               logger.error(`Email sending failed (attempt ${retries + 1}/${this.maxRetries})`, {
                    to: msg.to,
                    error: error.message,
                    code: error.code,
               });

               if (retries < this.maxRetries - 1) {
                    const delay = Math.pow(2, retries) * 1000;
                    await new Promise(resolve => setTimeout(resolve, delay));
                    return this.sendWithRetry(msg, retries + 1);
               }

               throw error;
          }
     }

     async sendOtpEmail(email, otp, ttlMinutes) {
          const msg = {
               to: email,
               from: this.from,
               subject: 'Your DesignKarle verification code',
               html: getOtpTemplate(otp, ttlMinutes),
          };

          return this.sendWithRetry(msg);
     }

     async sendWelcomeEmail(email, firstName) {
          const msg = {
               to: email,
               from: this.from,
               subject: 'Welcome to DesignKarle - Email Verified',
               html: getWelcomeTemplate(firstName),
          };

          return this.sendWithRetry(msg);
     }
}

module.exports = new EmailService();
