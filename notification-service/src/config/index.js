const config = {
     SERVICE_NAME: require('../../package.json').name,
     PORT: Number(process.env.PORT) || 4004,
     NODE_ENV: process.env.NODE_ENV || "development",
     LOG_LEVEL: process.env.LOG_LEVEL || "info",
     ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS,
     KAFKA_BROKER: process.env.KAFKA_BROKER,
     KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID,
     MAIL_SEND: process.env.MAIL_SEND,
     FRONTEND_URL: process.env.FRONTEND_URL,

     // SMTP / Nodemailer config
     SMTP_HOST: process.env.SMTP_HOST || 'smtp.gmail.com',
     SMTP_PORT: Number(process.env.SMTP_PORT) || 587,
     SMTP_USER: process.env.SMTP_USER,
     SMTP_PASS: process.env.SMTP_PASS,
}
module.exports = { config };
