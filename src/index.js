const Encrypter = require('./Illuminate/Encryption/Encrypter');
const EncryptError = require('./Illuminate/Encryption/EncryptError');
const DecryptError = require('./Illuminate/Encryption/DecryptError');
const RuntimeError = require('./Illuminate/Encryption/RuntimeError');

function fromRawKey(key) {
    return new Encrypter(key.startsWith('base64:') ? Buffer.from(key.substr(7), 'base64') : Buffer.from(key));
}

module.exports = {
    Encrypter,
    EncryptError,
    DecryptError,
    RuntimeError,
    fromEnv: () => fromRawKey(process.env.APP_KEY),
    fromRawKey,
};
