const crypto = require('crypto');

const header = {
    "typ": "JWT",
    "alg": "HS256"
};

const payload = {
    "name": "mark",
    "admin": true
};

const key = "xook";

const headerEncoded = Buffer.from(JSON.stringify(header))
    .toString('base64')
    .replace(/=/g, '');

const payloadEncoded = Buffer.from(JSON.stringify(payload))
    .toString('base64')
    .replace(/=/g, '');

const message = `${headerEncoded}.${payloadEncoded}`;

const signature = crypto.createHmac('sha256', key)
    .update(message)
    .digest('base64')
    .replace(/=/g, '');

const jwtToken = `${headerEncoded}.${payloadEncoded}.${signature}`;

console.log(jwtToken);
