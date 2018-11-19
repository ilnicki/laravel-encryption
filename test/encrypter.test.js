const chai = require('chai');
const expect = chai.expect;
const crypto = require('crypto');

const {Encrypter, RuntimeError, DecryptError, fromEnv} = require('../src');

describe('Encrypter', () => {
    /**
     * https://github.com/laravel/framework/blob/5.6/tests/Encryption/EncrypterTest.php
     */
    describe('laravel tests', () => {
        describe('testEncryption', function () {
            let e, encrypted;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                encrypted = e.encrypt('foo');
            });

            it('should not be equal "foo"', () => expect(encrypted).to.not.equal('foo'));
            it('should be equal "foo"', () => expect(e.decrypt(encrypted)).to.equal('foo'));
        });

        describe('testRawStringEncryption', function () {
            let e, encrypted;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                encrypted = e.encryptString('foo');
            });

            it('should not be equal "foo"', () => expect(encrypted).to.not.equal('foo'));
            it('should be equal "foo"', () => expect(e.decryptString(encrypted)).to.equal('foo'));
        });

        describe('testEncryptionUsingBase64EncodedKey', function () {
            let e, encrypted;

            before(() => {
                e = new Encrypter(crypto.randomBytes(16));
                encrypted = e.encrypt('foo');
            });

            it('should not be equal "foo"', () => expect(encrypted).to.not.equal('foo'));
            it('should be equal "foo"', () => expect(e.decrypt(encrypted)).to.equal('foo'));
        });

        describe('testWithCustomCipher', function () {
            describe('with 32 b\'s key', function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter('b'.repeat(32), 'AES-256-CBC');
                    encrypted = e.encrypt('bar');
                });

                it('should not be equal "bar"', () => expect(encrypted).to.not.equal('bar'));
                it('should be equal "bar"', () => expect(e.decrypt(encrypted)).to.equal('bar'));
            });

            describe('with random binary key', function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter(crypto.randomBytes(32), 'AES-256-CBC');
                    encrypted = e.encrypt('foo');
                });

                it('should not be equal "foo"', () => expect(encrypted).to.not.equal('foo'));
                it('should be equal "foo"', () => expect(e.decrypt(encrypted)).to.equal('foo'));
            });
        });

        it('testDoNoAllowLongerKey', () => expect(() => new Encrypter('z'.repeat(32)))
            .to.throw(RuntimeError, 'The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths'));

        it('testWithBadKeyLength', () => expect(() => new Encrypter('a'.repeat(5)))
            .to.throw(RuntimeError, 'The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths'));

        it('testWithBadKeyLengthAlternativeCipher', () => expect(() => new Encrypter('a'.repeat(16), 'AES-256-CFB8'))
            .to.throw(RuntimeError, 'The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths'));

        it('testWithUnsupportedCipher', () => expect(() => new Encrypter('c'.repeat(16), 'AES-256-CFB8'))
            .to.throw(RuntimeError, 'The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths'));

        describe('testExceptionThrownWhenPayloadIsInvalid', function () {
            let e, encrypted;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                encrypted = e.encrypt('foo').split('').sort(() => Math.random() > .5 ? -1 : 1).join('');
            });

            it('should throw with invalid json', () => expect(() => e.decrypt(encrypted)).to.throw(DecryptError, 'The JSON is invalid.'));
        });

        describe('testExceptionThrownWithDifferentKey', function () {
            let ea, eb;

            before(() => {
                ea = new Encrypter('a'.repeat(16));
                eb = new Encrypter('b'.repeat(16));
            });

            it('should throw with invalid mac', () => expect(() => eb.decrypt(ea.encrypt('baz'))).to.throw(DecryptError, 'The MAC is invalid.'));
        });

        describe('testExceptionThrownWhenIvIsTooLong', () => {
            let e, modifiedPayload;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                const payload = e.encrypt('foo');
                let data = JSON.parse(Buffer.from(payload, 'base64').toString());
                data.iv += data.value[0];
                data.value = data.value.substr(1);
                modifiedPayload = Buffer.from(JSON.stringify(data)).toString('base64');
            });

            it('should throw with invalid mac', () => expect(() => e.decrypt(modifiedPayload)).to.throw(DecryptError, 'The payload is invalid.'));
        });
    });

    describe('own tests', () => {
        describe('#constructor()', () => {
            describe('should success', () => {
                describe('on plain AES-128-CBC', () => {
                    let encrypter;

                    before(() => {
                        encrypter = new Encrypter('0123456789ABCDEF');
                    });

                    it('should contain key', () => {
                        expect(encrypter).to.have.property('key')
                            .with.lengthOf(16);
                    });

                    it('should use cipher AES-128-CBC', () => {
                        expect(encrypter).to.have.property('cipher')
                            .to.be.equal('AES-128-CBC');
                    });
                });

                describe('on base64 AES-128-CBC', () => {
                    let encrypter;

                    before(() => {
                        encrypter = new Encrypter(Buffer.from('0123456789ABCDEFGHIJKL==', 'base64'));
                    });

                    it('should contain key', () => {
                        expect(encrypter).to.have.property('key')
                            .with.lengthOf(16);
                    });
                });
            });

            describe('should throw', () => {
                it('should throw on wrong key length for AES-128-CBC', () => {
                    expect(() => {
                        new Encrypter('0123456789ABCDE');
                    }).to.throw(RuntimeError);
                });

                it('should throw on wrong key length for AES-128-CBC', function () {
                    expect(() => {
                        new Encrypter('0123456789ABCDEF', 'AES-256-CBC');
                    }).to.throw(RuntimeError);
                });
            });
        });

        describe('encrypt/decrypt big integers', () => {
            let e, original, encrypted, decrypted;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                original = Number.MAX_VALUE;
            });

            it('should encrypt', () => expect(() => encrypted = e.encrypt(original)).not.to.throw());
            it('should decrypt', () => expect(() => decrypted = e.decrypt(encrypted)).not.to.throw());
            it('should match', () => expect(decrypted).to.equal(original));
        });

        describe('encrypt/decrypt objects', () => {
            let e, original, encrypted, decrypted;

            before(() => {
                e = new Encrypter('a'.repeat(16));
                original = {
                    'x': 'y',
                    'z': 1,
                    'w': [Number.MIN_VALUE, Math.PI, Number.MAX_VALUE],
                };
            });

            it('should encrypt', () => expect(() => encrypted = e.encrypt(original)).not.to.throw());
            it('should decrypt', () => expect(() => decrypted = e.decrypt(encrypted)).not.to.throw());
            it('should match', () => expect(decrypted).to.deep.equal(original));
        });
    });

    describe('factory tests', () => {
        describe('from env', () => {
            describe('plain key', () => {
                let encrypter;
                let key = '0123456789ABCDEF';

                before(() => {
                    process.env.APP_KEY = key;
                    encrypter = fromEnv();
                });

                it('should contain key', () => {
                    expect(encrypter).to.have.property('key')
                        .with.lengthOf(16);
                });

                it('should equal key', () => {
                    expect(encrypter.key.toString()).to.equal(key);
                });
            });

            describe('base64 key', () => {
                let encrypter;
                let key = '0123456789ABCDEF';

                before(() => {
                    process.env.APP_KEY = `base64:${Buffer.from(key).toString('base64')}`;
                    encrypter = fromEnv();
                });

                it('should contain key', () => {
                    expect(encrypter).to.have.property('key')
                        .with.lengthOf(16);
                });

                it('should equal key', () => {
                    expect(encrypter.key.toString()).to.equal(key);
                });
            });
        });
    });

    describe('php tests', () => {
        const exec = require('util').promisify(require('child_process').exec);
        let PhpEncrypter;

        before(() => exec('composer install', {cwd: './test/laravel-encryption-test'}).then(() => {
            PhpEncrypter = function (key, cipher = 'AES-128-CBC') {
                return {
                    async call(method, ...params) {
                        const {stdout, stderr} = await exec('php call.php ' + JSON.stringify({
                            key,
                            cipher,
                            method,
                            params,
                        }).replace(/\x22/g, '\\\x22'), {cwd: './test/laravel-encryption-test'});

                        if (stderr) {
                            throw stderr;
                        } else {
                            return JSON.parse(stdout);
                        }
                    }
                };
            };
        }));

        describe('encoding', () => {
            let jsE;
            let phpE;

            before(() => {
                let key = 'a'.repeat(16);
                jsE = new Encrypter(key);
                phpE = new PhpEncrypter(key);
            });

            describe('encrypt', () => {
                [
                    null,
                    //undefined, // Crashes decryption
                    true,
                    false,
                    0,
                    1,
                    Number.MAX_VALUE,
                    Number.MIN_VALUE,
                    Math.PI,
                    '',
                    'foo',
                    Array(500).fill(null).map(() => Math.random().toString(36).substring(2, 15)).join(''),
                    [],
                    ['bar'],
                    //{}, // Deserializer fails on stdClass
                    //{'foo': 'bar'}, // Deserializer fails on stdClass
                ].forEach(value => it(`should be equal ${JSON.stringify(value)}`, () =>
                    phpE.call('encrypt', value).then((ret) => expect(jsE.decrypt(ret)).to.deep.equal(value))
                ));
            });

            describe('decrypt', () => {
                [
                    null,
                    //undefined, // Crashes encryption
                    true,
                    false,
                    0,
                    1,
                    Number.MAX_VALUE,
                    Number.MIN_VALUE,
                    Math.PI,
                    '',
                    'foo',
                    Array(500).fill(null).map(() => Math.random().toString(36).substring(2, 15)).join(''),
                    [],
                    ['bar'],
                    //{}, // Empty object turns into the empty array
                    {'foo': 'bar'},
                ].forEach(value => it(`should be equal ${JSON.stringify(value)}`, () =>
                    phpE.call('decrypt', jsE.encrypt(value)).then((ret) => expect(ret).to.deep.equal(value))
                ));
            });

            describe('encryptString', () => {
                it('should be equal "foo"', () => {
                    let value = 'foo';
                    phpE.call('encryptString', value).then((ret) => expect(jsE.decryptString(ret)).to.equal(value));
                });

                it('should be equal generated value', () => {
                    let value = Array(500).fill(null).map(() => Math.random().toString(36).substring(2, 15)).join('');
                    phpE.call('encryptString', value).then((ret) => expect(jsE.decryptString(ret)).to.equal(value));
                });
            });

            describe('decryptString', () => {
                it('should be equal "foo"', () => {
                    let value = 'foo';
                    let jsEncrypted = jsE.encryptString(value);

                    phpE.call('decryptString', jsEncrypted).then((ret) => expect(ret).to.equal(value));
                });

                it('should be equal generated value', () => {
                    let value = Array(500).fill(null).map(() => Math.random().toString(36).substring(2, 15)).join('');
                    let jsEncrypted = jsE.encryptString(value);

                    phpE.call('decryptString', jsEncrypted).then((ret) => expect(ret).to.equal(value));
                });
            });
        });
    });
});