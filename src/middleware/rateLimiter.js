const rateLimit = require("express-rate-limit");

const authLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,   // 1 minute
    max: 10,                   // max 10 requests per IP per minute
    message: { error: "Too many requests, try again later." }
});

module.exports = authLimiter;
