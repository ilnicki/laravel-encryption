const Encrypter = require("./Illuminate/Encryption/Encrypter");


module.exports = {
    Encrypter,
    fromEnv() {
        return this.fromRawKey(process.env.APP_KEY);
    },
    fromRawKey(key) {
        return new Encrypter(key.startsWith("base64:") ? Buffer.from(key.substr(7), "base64") : Buffer.from(key));
    }
};