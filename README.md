# laravel-encryption
The Illuminate Encryption component from Laravel pure js implementation.
The Laravel Encryption is node library that helps you to encode/decode data in compatible with Laravel way.

Basic usage:
```js
const encryption = require('laravel-encryption');

let encrypter = new encryption.Encrypter("your-secret-key-");

// or
let encrypter = new encryption.fromRawKey("base64:eW91ci1zZWNyZXQta2V5LQ==");

// or
let encrypter = new encryption.fromEnv();

let encrypted = encrypter.encrypt({"key": "value"});
let decrypted = encrypter.decrypt(encrypted);

```

The library tries to be as close to original as possible so you can refer to Laravel docs.