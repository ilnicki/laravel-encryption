const crypto = require("crypto");
const Serialize = require('php-serialize');

const RuntimeError = require("./RuntimeError");
const EncryptError = require("./EncryptError");
const DecryptError = require("./DecryptError");

/**
 * Illuminate\Encryption\Encrypter
 * @property {Buffer} key The encryption key.
 * @access protected
 * @property {string} cipher The algorithm used for encryption.
 * @access protected
 */
class Encrypter {
    /**
     * Create a new encrypter instance.
     * @param {string|Buffer} key - The encryption key.
     * @param {string} cipher - The encryption algorithm name.
     */
    constructor(key, cipher = "AES-128-CBC") {
        key = Buffer.from(key);

        if (Encrypter.supported(key, cipher)) {
            this.key = key;
            this.cipher = cipher;
        } else {
            throw new RuntimeError(`The only supported ciphers are [${Object.keys(Encrypter.getCipher()).join(', ')}] with the correct key lengths.`);
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     * @param {Buffer} key - The encryption key.
     * @param {string} cipher - The encryption algorithm name.
     * @return {boolean} The status of the key-cipher combination availability.
     */
    static supported(key, cipher) {
        const cipherDesc = Encrypter.getCipher(cipher);
        return cipherDesc && key.length === cipherDesc.key.length;
    }

    /**
     * Returns description for supported cipher or full list of them
     * @param {string|undefined} cipher - The encryption algorithm name.
     * @returns {object} The descriptor object for selected algorithm or if non selected the full list of descriptors.
     */
    static getCipher(cipher) {
        const ciphers = {
            "AES-128-CBC": {
                key: {
                    length: 16
                },
                iv: {
                    length: 16
                }
            },
            "AES-256-CBC": {
                key: {
                    length: 32
                },
                iv: {
                    length: 16
                }
            },
        };

        return cipher ? ciphers[cipher] : ciphers;
    }

    /**
     * Create a new encryption key for the given cipher.
     * @param {string} cipher - The encryption algorithm name.
     * @return {string} The encryption key.
     */
    static generateKey(cipher) {
        return crypto.randomBytes(Encrypter.getCipher(cipher).key.length);
    }

    /**
     * Encrypt the given value.
     * @param {Object} value
     * @param {boolean} serialize
     * @return {string}
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    encrypt(value, serialize = true) {
        let iv = crypto.randomBytes(Encrypter.getCipher(this.cipher).iv.length);
        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        const cipher = crypto.createCipheriv(this.cipher, this.key, iv);

        try {
            value = Buffer.concat([
                cipher.update(serialize ? Serialize.serialize(value) : value),
                cipher.final()
            ]).toString("base64");
        } catch (e) {
            throw new EncryptError("Could not encrypt the data.");
        }

        // Once we get the encrypted value we'll go ahead and base64.encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        let mac = this.hash(iv = Buffer.from(iv, "binary").toString("base64"), value);
        return Buffer.from(JSON.stringify({iv, value, mac}), "utf8").toString("base64");
    }

    /**
     * Encrypt a string without serialization.
     * @param {string} value
     * @return {string}
     */
    encryptString(value) {
        return this.encrypt(value, false);
    }

    /**
     * Decrypt the given value.
     * @param {string} payload
     * @param {boolean} unserialize
     * @return {string}
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    decrypt(payload, unserialize = true) {
        const jsonPayload = this.getJsonPayload(payload);
        const iv = Buffer.from(jsonPayload.iv, "base64");
        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        const decipher = crypto.createDecipheriv(this.cipher, this.key, iv);
        //decipher.setAutoPadding(false);
        let decryptedPayload;

        try {
            decryptedPayload = Buffer.concat([
                decipher.update(Buffer.from(jsonPayload.value, "base64")),
                decipher.final()
            ]).toString("utf8");
        } catch (e) {
            throw new DecryptError("Could not decrypt the data.");
        }

        try {
            return unserialize ? Serialize.unserialize(decryptedPayload) : decryptedPayload;
        } catch (e) {
            throw new DecryptError("Could not unserialize the data.");
        }
    }

    /**
     * Decrypt the given string without unserialization.
     * @param {string} payload
     * @return {string}
     */
    decryptString(payload) {
        return this.decrypt(payload, false);
    }

    /**
     * Create a MAC for the given value.
     * @access protected
     * @param {string} iv
     * @param  {string}  value
     * @return {Buffer}
     */
    hash(iv, value) {
        let hmac = crypto.createHmac('sha256', this.key);
        hmac.update(iv.concat(value), "utf8");
        return hmac.digest().toString("hex");
    }

    /**
     * Get the JSON array from the given payload.
     * @access protected
     * @param {string} payload
     * @return {Object}
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    getJsonPayload(payload) {
        try {
            payload = JSON.parse(Buffer.from(payload, 'base64').toString("utf8"));
        } catch (e) {
            throw new DecryptError("The JSON is invalid.");
        }

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!this.validPayload(payload)) {
            throw new DecryptError("The payload is invalid.");
        }

        if (!this.validMac(payload)) {
            throw new DecryptError("The MAC is invalid.");
        }

        return payload;
    }

    /**
     * Verify that the encryption payload is valid.
     * @access protected
     * @param  {object}  payload
     * @return {boolean}
     */
    validPayload(payload) {
        let iv;
        return typeof payload === "object"
            && payload.hasOwnProperty("iv")
            && payload.hasOwnProperty("value")
            && payload.hasOwnProperty("mac")
            && (iv = Buffer.from(payload.iv, "base64"))
            && iv.length === Encrypter.getCipher(this.cipher).iv.length
            && payload.iv === iv.toString("base64");
    }

    /**
     * Determine if the MAC for the given payload is valid.
     * @access protected
     * @param {object} payload
     * @return {boolean}
     */
    validMac(payload) {
        let bytes = crypto.randomBytes(16),
            calculated = this.calculateMac(payload, bytes),
            hmac = crypto.createHmac('sha256', bytes);
        hmac.update(payload.mac);
        return crypto.timingSafeEqual(hmac.digest(), calculated);
    }

    /**
     * Calculate the hash of the given payload.
     * @access protected
     * @param {object} payload
     * @param {Buffer} bytes
     * @return {Buffer}
     */
    calculateMac(payload, bytes) {
        const hmac = crypto.createHmac('sha256', bytes);
        hmac.update(this.hash(payload.iv, payload.value));
        return hmac.digest();
    }

    /**
     * Get the encryption key.
     * @return {Buffer}
     */
    getKey() {
        return this.key;
    }
}

module.exports = Encrypter;