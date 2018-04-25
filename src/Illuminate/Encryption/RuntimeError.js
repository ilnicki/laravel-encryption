class RuntimeError extends Error {
    constructor(...args) {
        super(...args);
        Error.captureStackTrace(this, RuntimeError)
    }
}

module.exports = RuntimeError;