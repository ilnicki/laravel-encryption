# laravel-encryption
The Illuminate Encryption component from Laravel pure js implementation.
The Laravel Encryption is node library that helps you to encode/decode data in compatible with Laravel way.

Basic usage:
```js
const Encrypter = require("laravel-encryption").Encrypter;

let encrypter = new Encrypter("your-secret-key-");

let encrypted = encrypter.encrypt({"key": "value"});

let decrypted = encrypter.decrypt(encrypted);

```

The library tries to be as close to original as possible so you can refer to Laravel docs.