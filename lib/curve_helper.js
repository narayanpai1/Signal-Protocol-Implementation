var crypt = require('./curve25519_compiled');

var Internal = Internal || {};

(function() {
    'use strict';

    // Insert some bytes into the emscripten memory and return a pointer
    function _allocate(bytes) {
        var address = crypt._malloc(bytes.length);
        crypt.HEAPU8.set(bytes, address);

        return address;
    }

    function _readBytes(address, length, array) {
        array.set(crypt.HEAPU8.subarray(address, address + length));
    }

    var basepoint = new Uint8Array(32);
    basepoint[0] = 9;

    Internal.curve25519 = {
        keyPair: function(privKey) {
            var priv = new Uint8Array(privKey);
            priv[0]  &= 248;
            priv[31] &= 127;
            priv[31] |= 64;

            // Where to store the result
            var publicKey_ptr = crypt._malloc(32);

            // Get a pointer to the private key
            var privateKey_ptr = _allocate(priv);

            // The basepoint for generating public keys
            var basepoint_ptr = _allocate(basepoint);

            // The return value is just 0, the operation is done in place
            var err = crypt._curve25519_donna(publicKey_ptr,
                                            privateKey_ptr,
                                            basepoint_ptr);

            var res = new Uint8Array(32);
            _readBytes(publicKey_ptr, 32, res);

            crypt._free(publicKey_ptr);
            crypt._free(privateKey_ptr);
            crypt._free(basepoint_ptr);

            return { pubKey: res.buffer, privKey: priv.buffer };
        },
        sharedSecret: function(pubKey, privKey) {
            // Where to store the result
            var sharedKey_ptr = crypt._malloc(32);

            // Get a pointer to our private key
            var privateKey_ptr = _allocate(new Uint8Array(privKey));

            // Get a pointer to their public key, the basepoint when you're
            // generating a shared secret
            var basepoint_ptr = _allocate(new Uint8Array(pubKey));

            // Return value is 0 here too of course
            var err = crypt._curve25519_donna(sharedKey_ptr,
                                               privateKey_ptr,
                                               basepoint_ptr);

            var res = new Uint8Array(32);
            _readBytes(sharedKey_ptr, 32, res);

            crypt._free(sharedKey_ptr);
            crypt._free(privateKey_ptr);
            crypt._free(basepoint_ptr);

            return res.buffer;
        },
        sign: function(privKey, message) {
            // Where to store the result
            var signature_ptr = crypt._malloc(64);

            // Get a pointer to our private key
            var privateKey_ptr = _allocate(new Uint8Array(privKey));

            // Get a pointer to the message
            var message_ptr = _allocate(new Uint8Array(message));

            var err = crypt._curve25519_sign(signature_ptr,
                                              privateKey_ptr,
                                              message_ptr,
                                              message.byteLength);

            var res = new Uint8Array(64);
            _readBytes(signature_ptr, 64, res);

            crypt._free(signature_ptr);
            crypt._free(privateKey_ptr);
            crypt._free(message_ptr);

            return res.buffer;
        },
        verify: function(pubKey, message, sig) {
            // Get a pointer to their public key
            var publicKey_ptr = _allocate(new Uint8Array(pubKey));

            // Get a pointer to the signature
            var signature_ptr = _allocate(new Uint8Array(sig));

            // Get a pointer to the message
            var message_ptr = _allocate(new Uint8Array(message));

            var res = crypt._curve25519_verify(signature_ptr,
                                                publicKey_ptr,
                                                message_ptr,
                                                message.byteLength);

            crypt._free(publicKey_ptr);
            crypt._free(signature_ptr);
            crypt._free(message_ptr);

            return res !== 0;
        }
    };

    Internal.curve25519_async = {
        keyPair: function(privKey) {
            return new Promise(function(resolve) {
                resolve(Internal.curve25519.keyPair(privKey));
            });
        },
        sharedSecret: function(pubKey, privKey) {
            return new Promise(function(resolve) {
                resolve(Internal.curve25519.sharedSecret(pubKey, privKey));
            });
        },
        sign: function(privKey, message) {
            return new Promise(function(resolve) {
                resolve(Internal.curve25519.sign(privKey, message));
            });
        },
        verify: function(pubKey, message, sig) {
            return new Promise(function(resolve, reject) {
                if (Internal.curve25519.verify(pubKey, message, sig)) {
                    reject(new Error("Invalid signature"));
                } else {
                    resolve();
                }
            });
        },
    };

})();


function validatePrivKey(privKey) {
    if (privKey === undefined || !(privKey instanceof ArrayBuffer) || privKey.byteLength != 32) {
        throw new Error("Invalid private key");
    }
}
function validatePubKeyFormat(pubKey) {
    if (pubKey === undefined || ((pubKey.byteLength != 33 || new Uint8Array(pubKey)[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

function processKeys(raw_keys) {
    // prepend version byte
    var origPub = new Uint8Array(raw_keys.pubKey);
    var pub = new Uint8Array(33);
    pub.set(origPub, 1);
    pub[0] = 5;

    return { pubKey: pub.buffer, privKey: raw_keys.privKey };
}

function wrapCurve25519(curve25519) {
    return {
        // Curve 25519 crypto
        createKeyPair: function(privKey) {
            validatePrivKey(privKey);
            var raw_keys = curve25519.keyPair(privKey);
            if (raw_keys instanceof Promise) {
                return raw_keys.then(processKeys);
            } else {
                return processKeys(raw_keys);
            }
        },
        ECDHE: function(pubKey, privKey) {
            pubKey = validatePubKeyFormat(pubKey);
            validatePrivKey(privKey);

            if (pubKey === undefined || pubKey.byteLength != 32) {
                throw new Error("Invalid public key");
            }

            return curve25519.sharedSecret(pubKey, privKey);
        },
        Ed25519Sign: function(privKey, message) {
            validatePrivKey(privKey);

            if (message === undefined) {
                throw new Error("Invalid message");
            }

            return curve25519.sign(privKey, message);
        },
        Ed25519Verify: function(pubKey, msg, sig) {
            pubKey = validatePubKeyFormat(pubKey);

            if (pubKey === undefined || pubKey.byteLength != 32) {
                throw new Error("Invalid public key");
            }

            if (msg === undefined) {
                throw new Error("Invalid message");
            }

            if (sig === undefined || sig.byteLength != 64) {
                throw new Error("Invalid signature");
            }

            return curve25519.verify(pubKey, msg, sig);
        }
    };
}

module.exports = {
    Curve:wrapCurve25519(Internal.curve25519),
    Curveasync:wrapCurve25519(Internal.curve25519_async)
}