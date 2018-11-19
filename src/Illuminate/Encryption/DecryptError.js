class DecryptError extends Error {
    constructor(...args) {
        super(...args);
        Error.captureStackTrace(this, DecryptError);
    }
}

module.exports = DecryptError;
