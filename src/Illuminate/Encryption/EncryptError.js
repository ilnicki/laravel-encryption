class EncryptError extends Error {
    constructor(...args) {
        super(...args);
        Error.captureStackTrace(this, EncryptError);
    }
}

module.exports = EncryptError;
