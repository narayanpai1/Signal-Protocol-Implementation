var crypto = require("crypto").webcrypto;
var curveCrypto = require("./lib/curve_helper");
var nodeCrypto = require("crypto");

let sign = function (key, data) {
    return crypto.subtle
        .importKey(
            "raw",
            key,
            { name: "HMAC", hash: { name: "SHA-256" } },
            false,
            ["sign"]
        )
        .then(function (key) {
            return crypto.subtle.sign(
                { name: "HMAC", hash: "SHA-256" },
                key,
                data
            );
        });
};

function toArrayBuffer(buf) {
    var ab = new ArrayBuffer(buf.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
    }
    return ab;
}

function toBuffer(ab) {
    var buf = Buffer.alloc(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        buf[i] = view[i];
    }
    return buf;
}

module.exports = {
    getRandomBytes: function (size) {
        var array = new Uint8Array(size);
        crypto.getRandomValues(array);
        return array.buffer;
    },
    encrypt: function (key, data, iv) {
        var cipher = nodeCrypto.createCipher("aes-192-cbc", key);
        var crypted = Buffer.concat([
            cipher.update(toBuffer(data)),
            cipher.final(),
        ]);
        return toArrayBuffer(crypted);
    },
    decrypt: function (key, data, iv) {
        var decipher = nodeCrypto.createDecipher("aes-192-cbc", key);
        var dec = Buffer.concat([
            decipher.update(toBuffer(data)),
            decipher.final(),
        ]);
        return toArrayBuffer(dec);
    },

    hash: function (data) {
        return crypto.subtle.digest({ name: "SHA-512" }, data);
    },

    KDF: function (input, salt, info) {
        if (salt.byteLength != 32) {
            throw new Error("Got salt of incorrect length");
        }

        return sign(salt, input).then(function (PRK) {
            var infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32);
            var infoArray = new Uint8Array(infoBuffer);
            infoArray.set(new Uint8Array(info), 32);
            infoArray[infoArray.length - 1] = 1;
            return sign(PRK, infoBuffer.slice(32)).then(function (T1) {
                infoArray.set(new Uint8Array(T1));
                infoArray[infoArray.length - 1] = 2;
                return sign(PRK, infoBuffer).then(function (T2) {
                    return [T1, T2];
                });
            });
        });
    },

    // Curve 25519 crypto
    createKeyPair: function (privKey) {
        if (privKey === undefined) {
            privKey = this.getRandomBytes(32);
        }
        return curveCrypto.Curveasync.createKeyPair(privKey);
    },
    ECDHE: function (pubKey, privKey) {
        return curveCrypto.Curveasync.ECDHE(pubKey, privKey);
    },
    Ed25519Sign: function (privKey, message) {
        return curveCrypto.Curveasync.Ed25519Sign(privKey, message);
    },
    Ed25519Verify: function (pubKey, msg, sig) {
        return curveCrypto.Curveasync.Ed25519Verify(pubKey, msg, sig);
    },
    verifyMAC: function (data, key, mac, length) {
        return sign(key, data).then(function (calculated_mac) {
            if (
                mac.byteLength != length ||
                calculated_mac.byteLength < length
            ) {
                throw new Error("Bad MAC length");
            }
            var a = new Uint8Array(calculated_mac);
            var b = new Uint8Array(mac);
            var result = 0;
            for (var i = 0; i < mac.byteLength; ++i) {
                result = result | (a[i] ^ b[i]);
            }
            if (result !== 0) {
                throw new Error("Bad MAC");
            }
        });
    },
};
