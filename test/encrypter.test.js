const chai = require("chai");
const expect = chai.expect;
const crypto = require("crypto");

const Encrypter = require("../src/Illuminate/Encryption/Encrypter");
const RuntimeError = require("../src/Illuminate/Encryption/RuntimeError");
const DecryptError = require("../src/Illuminate/Encryption/DecryptError");
const EncryptError = require("../src/Illuminate/Encryption/EncryptError");


describe("Encrypter", () => {
    describe("#constructor()", () => {
        describe("should success", () => {
            describe("on plain AES-128-CBC", () => {
                let encrypter;

                before(() => {
                    encrypter = new Encrypter("0123456789ABCDEF");
                });

                it("should contain key", () => {
                    expect(encrypter).to.have.property("key")
                        .with.lengthOf(16);
                });

                it("should use cipher AES-128-CBC", () => {
                    expect(encrypter).to.have.property("cipher")
                        .to.be.equal('AES-128-CBC');
                });
            });

            describe("on base64 AES-128-CBC", () => {
                let encrypter;

                before(() => {
                    encrypter = new Encrypter(Buffer.from("0123456789ABCDEFGHIJKL==", "base64"));
                });

                it("should contain key", () => {
                    expect(encrypter).to.have.property("key")
                        .with.lengthOf(16);
                });
            });
        });

        describe("should throw", () => {
            it("should throw on wrong key length for AES-128-CBC", () => {
                expect(() => {
                    new Encrypter("0123456789ABCDE");
                }).to.throw(RuntimeError);
            });

            it("should throw on wrong key length for AES-128-CBC", function () {
                expect(() => {
                    new Encrypter("0123456789ABCDEF", "AES-256-CBC");
                }).to.throw(RuntimeError);
            });
        });

        /**
         * https://github.com/laravel/framework/blob/5.6/tests/Encryption/EncrypterTest.php
         */
        describe("laravel tests", () => {
            describe("testEncryption", function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter("a".repeat(16));
                    encrypted = e.encrypt("foo");
                });

                it("should not be equal 'foo'", () => expect(encrypted).to.not.equal("foo"));
                it("should be equal 'foo'", () => expect(e.decrypt(encrypted)).to.equal("foo"));
            });

            describe("testRawStringEncryption", function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter("a".repeat(16));
                    encrypted = e.encryptString("foo");
                });

                it("should not be equal 'foo'", () => expect(encrypted).to.not.equal("foo"));
                it("should be equal 'foo'", () => expect(e.decryptString(encrypted)).to.equal("foo"));
            });

            describe("testEncryptionUsingBase64EncodedKey", function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter(crypto.randomBytes(16));
                    encrypted = e.encrypt("foo");
                });

                it("should not be equal 'foo'", () => expect(encrypted).to.not.equal("foo"));
                it("should be equal 'foo'", () => expect(e.decrypt(encrypted)).to.equal("foo"));
            });

            describe("testWithCustomCipher", function () {
                describe("with 32 b's key", function () {
                    let e, encrypted;

                    before(() => {
                        e = new Encrypter("b".repeat(32), "AES-256-CBC");
                        encrypted = e.encrypt("bar");
                    });

                    it("should not be equal 'bar'", () => expect(encrypted).to.not.equal("bar"));
                    it("should be equal 'bar'", () => expect(e.decrypt(encrypted)).to.equal("bar"));
                });

                describe("with random binary key", function () {
                    let e, encrypted;

                    before(() => {
                        e = new Encrypter(crypto.randomBytes(32), "AES-256-CBC");
                        encrypted = e.encrypt("foo");
                    });

                    it("should not be equal 'foo'", () => expect(encrypted).to.not.equal("foo"));
                    it("should be equal 'foo'", () => expect(e.decrypt(encrypted)).to.equal("foo"));
                });
            });

            it("testDoNoAllowLongerKey", () => expect(() => new Encrypter("z".repeat(32)))
                .to.throw(RuntimeError, "The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths"));

            it("testWithBadKeyLength", () => expect(() => new Encrypter("a".repeat(5)))
                .to.throw(RuntimeError, "The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths"));

            it("testWithBadKeyLengthAlternativeCipher", () => expect(() => new Encrypter("a".repeat(16), "AES-256-CFB8"))
                .to.throw(RuntimeError, "The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths"));

            it("testWithUnsupportedCipher", () => expect(() => new Encrypter("c".repeat(16), "AES-256-CFB8"))
                .to.throw(RuntimeError, "The only supported ciphers are [AES-128-CBC, AES-256-CBC] with the correct key lengths"));

            describe("testExceptionThrownWhenPayloadIsInvalid", function () {
                let e, encrypted;

                before(() => {
                    e = new Encrypter("a".repeat(16));
                    encrypted = e.encrypt("foo").split("").sort(() => Math.random() > .5 ? -1 : 1).join("");
                });

                it("should throw with invalid json", () => expect(() => e.decrypt(encrypted)).to.throw(DecryptError, "The JSON is invalid."));
            });

            describe("testExceptionThrownWithDifferentKey", function () {
                let ea, eb;

                before(() => {
                    ea = new Encrypter("a".repeat(16));
                    eb = new Encrypter("b".repeat(16));
                });

                it("should throw with invalid mac", () => expect(() => eb.decrypt(ea.encrypt("baz"))).to.throw(DecryptError, "The MAC is invalid."));
            });

            describe("testExceptionThrownWhenIvIsTooLong", () => {
                let e, modifiedPayload;

                before(() => {
                    e = new Encrypter("a".repeat(16));
                    const payload = e.encrypt("foo");
                    let data = JSON.parse(Buffer.from(payload, "base64").toString());
                    data.iv += data.value[0];
                    data.value = data.value.substr(1);
                    modifiedPayload = Buffer.from(JSON.stringify(data)).toString("base64");
                });

                it("should throw with invalid mac", () => expect(() => e.decrypt(modifiedPayload)).to.throw(DecryptError, "The payload is invalid."));
            });

            it("temp", () => {
                let e = new Encrypter("a".repeat(16));
                let x = e.decrypt("eyJpdiI6InlWVzYzRldTZ3MyQTJEY1VwMW1BWGc9PSIsInZhbHVlIjoiOGZTS0gxY2FTQ3R2M0FyY0EzdjZKa1E0ak9LTHlxd2Fjc1N5akEzYVdOdllXUVF5YTJBeDlPbjJkWVVxKzdvMHg4VVZcLzkxY01QVlBmMU94dmRTVVhzQW5ZM3FNOUZ4dUZHYWY5SzJZdHRnMDFqc0JFRk85YXVjQTgrSitqbnpqWUNhXC84dUxpUlVVTDdkOHVHeEhqa1VcL29xWGFUQStZc29jTWRLY3FaK2JuZ3ZxQVd6K3dxQnJSbTY0d3V4TFlVN21WWnIzRG9xZXROdVwvR0k1TFhSTWhYZUk5SmhoOGljV1wveWZkM1oyTDhnPSIsIm1hYyI6IjYxYzVhNmU4MGUzYTlkN2IyOTExZTYwNWI3YTRkZTc3YTFjNmI3MGIyNGVlYmU4YzcxMDIxMDk1MjNhN2I2NjUifQ==");
                console.log(x);
            });
        });
    });
});