const config = {
    SERVICE_NAME: require('../../package.json').name,

    PORT: Number(process.env.PORT) || 4001,
    NODE_ENV: process.env.NODE_ENV || 'development',
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',

    DATABASE_URL: process.env.DATABASE_URL,
    REDIS_URL: process.env.REDIS_URL,
    KAFKA_BROKER: process.env.KAFKA_BROKER,
    KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID,
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS,

    OTP_TTL: Number(process.env.OTP_TTL || 300),
    OTP_RATE_MAX_PER_HOUR: Number(process.env.OTP_RATE_MAX_PER_HOUR || 5),
    OTP_MAX_VERIFY_ATTEMPTS: Number(process.env.OTP_MAX_VERIFY_ATTEMPTS || 5),
    OTP_HMAC_SECRET: process.env.OTP_HMAC_SECRET || '',

    JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || '',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || '',

    ACCESS_TOKEN_EXP: process.env.ACCESS_TOKEN_EXP || '15m',
    REFRESH_TOKEN_EXP: process.env.REFRESH_TOKEN_EXP || '7d',

    ACCESS_TOKEN_EXP_SEC: Number(process.env.ACCESS_TOKEN_EXP_SEC || 900),
    REFRESH_TOKEN_EXP_SEC: Number(process.env.REFRESH_TOKEN_EXP_SEC || 604800),
    REDIS_USER_TTL: Number(process.env.REDIS_USER_TTL || 86400),

    MAIL_SEND: process.env.MAIL_SEND,
    SENDGRID_API_KEY: process.env.SENDGRID_API_KEY,

    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,

    INTERNAL_SERVICE_KEY: process.env.INTERNAL_SERVICE_KEY || '',
};


// ============================================================
// FAIL-FAST ENVIRONMENT VARIABLE VALIDATION
// ============================================================

const requiredEnvVariables = [
    'DATABASE_URL',
    'REDIS_URL',
    'KAFKA_BROKER',
    'KAFKA_CLIENT_ID',

    'OTP_HMAC_SECRET',

    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',

    'SENDGRID_API_KEY',
    'MAIL_SEND',

    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',

    'INTERNAL_SERVICE_KEY',
];


// Validate required environment variables
const missingVariables = requiredEnvVariables.filter((key) => {
    const value = config[key];

    return (
        value === undefined ||
        value === null ||
        (typeof value === 'string' && value.trim() === '')
    );
});

if (missingVariables.length > 0) {
    throw new Error(
        `[CONFIG ERROR] Missing or empty required environment variables:\n` +
        missingVariables.map((key) => `  - ${key}`).join('\n') +
        '\n\nApplication startup aborted.'
    );
}


// ============================================================
// CRYPTOGRAPHIC SECRET VALIDATION
// ============================================================

const secretVariables = [
    'OTP_HMAC_SECRET',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
    'INTERNAL_SERVICE_KEY',
];

const invalidSecrets = secretVariables.filter(
    (key) => config[key].length < 32
);

if (invalidSecrets.length > 0) {
    throw new Error(
        `[CONFIG ERROR] The following secrets must contain at least 32 characters:\n` +
        invalidSecrets.map((key) => `  - ${key}`).join('\n') +
        '\n\nApplication startup aborted.'
    );
}


// ============================================================
// NUMERIC CONFIGURATION VALIDATION
// ============================================================

const numericVariables = [
    'PORT',
    'OTP_TTL',
    'OTP_RATE_MAX_PER_HOUR',
    'OTP_MAX_VERIFY_ATTEMPTS',
    'ACCESS_TOKEN_EXP_SEC',
    'REFRESH_TOKEN_EXP_SEC',
    'REDIS_USER_TTL',
];

const invalidNumericVariables = numericVariables.filter(
    (key) =>
        !Number.isFinite(config[key]) ||
        config[key] <= 0
);

if (invalidNumericVariables.length > 0) {
    throw new Error(
        `[CONFIG ERROR] Invalid numeric environment variables:\n` +
        invalidNumericVariables.map((key) => `  - ${key}`).join('\n') +
        '\n\nApplication startup aborted.'
    );
}


// ============================================================
// EXPORT CONFIGURATION
// ============================================================

module.exports = { config };