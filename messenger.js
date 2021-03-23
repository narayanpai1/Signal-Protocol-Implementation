let helper = require("./helper");
const crypto = require("./crypto");

class Messenger {
    constructor(userDetails, myDetails) {
        for (let prop in myDetails) {
            this[prop] = myDetails[prop];
        }
        for (let prop in userDetails) {
            this[prop] = userDetails[prop];
            if (typeof this[prop] === "string") {
                this[prop] = helper.base64ToArrayBuffer(this[prop]);
            }
        }
        this.initialMessage = true;
        this.associatedData = helper.appendBuffer(
            this.myIdentityKey.pubKey,
            this.identityKey
        );

        let tempArr = [];
        for (let i = 0; i < 32; i++) {
            tempArr.push(i);
        }
        this.kdfInfo = new Uint8Array(tempArr);

        this.iv = new Uint8Array(16);
    }

    async resetRatchets() {
        this.currRatchetInput = await crypto.ECDHE(
            this.currPublicKey,
            this.myCurrRatchetKey.privKey
        );

        [this.sendRatchetKey, this.rootRatchetKey] = await crypto.KDF(
            this.currRatchetInput,
            this.rootRatchetKey,
            this.kdfInfo
        );
        [this.recvRatchetKey, this.rootRatchetKey] = await crypto.KDF(
            this.currRatchetInput,
            this.rootRatchetKey,
            this.kdfInfo
        );
    }

    async sendInitialMessage() {
        try {
            await crypto.Ed25519Verify(
                this.identityKey,
                this.preKey,
                this.preKeySig
            );
        } catch (e) {
            console.log("PreKey signature invalid");
            process.exit();
        }

        this.initialMessage = false;
        this.ephemeralKey = await crypto.createKeyPair();
        let dh1 = await crypto.ECDHE(this.preKey, this.myIdentityKey.privKey);
        let dh2 = await crypto.ECDHE(
            this.identityKey,
            this.ephemeralKey.privKey
        );
        let dh3 = await crypto.ECDHE(this.preKey, this.ephemeralKey.privKey);
        let dh4 = await crypto.ECDHE(
            this.oneTimePreKey,
            this.ephemeralKey.privKey
        );

        this.key = dh1 + dh2 + dh3 + dh4;
        this.key = await crypto.hash(this.key);
        this.key = this.key.slice(0, 32);
        // console.log(this.key);
        // console.log(this.associatedData);
        // console.log(this.iv);

        let initialCipherMessage = await crypto.encrypt(
            this.key,
            this.associatedData,
            this.iv
        );
        console.log(initialCipherMessage);

        this.rootRatchetKey = this.key;

        let rv = {
            identityKey: this.myIdentityKey.pubKey,
            ephemeralKey: this.ephemeralKey.pubKey,
            preKey: this.oneTimePreKey,
            message: initialCipherMessage,
        };
        rv = helper.toBase64Obj(rv);
        return rv;
    }

    async send(message) {
        this.myCurrRatchetKey = await crypto.createKeyPair();
        await this.resetRatchets();

        let currEncryptionKey;
        [this.sendRatchetKey, currEncryptionKey] = await crypto.KDF(
            this.currRatchetInput,
            this.sendRatchetKey,
            this.kdfInfo
        );
        let cipherMessage = await crypto.encrypt(
            currEncryptionKey,
            helper.base64ToArrayBuffer(
                Buffer.from(message, "utf8").toString("base64")
            ),
            this.iv
        );

        let rv = {
            currPublicKey: this.myCurrRatchetKey.pubKey,
            message: cipherMessage,
        };
        rv = helper.toBase64Obj(rv);
        return rv;
    }

    async receiveInitialMessage(message) {
        message = helper.toArrayBufferObj(message);
        this.initialMessage = false;

        // find the onetime key used by the sender and store it in 'otkey' and delete it from the array
        let otkey;
        for (let i in this.myOneTimePreKeys) {
            if (
                helper.arrayBufferToBase64(message.preKey) ==
                helper.arrayBufferToBase64(this.myOneTimePreKeys[i].pubKey)
            ) {
                otkey = this.myOneTimePreKeys[i];
                this.myOneTimePreKeys.splice(i, 1);
            }
        }

        let dh1 = await crypto.ECDHE(
            message.identityKey,
            this.myPreKey.privKey
        );
        let dh2 = await crypto.ECDHE(
            message.ephemeralKey,
            this.myIdentityKey.privKey
        );
        let dh3 = await crypto.ECDHE(
            message.ephemeralKey,
            this.myPreKey.privKey
        );
        let dh4 = await crypto.ECDHE(message.ephemeralKey, otkey.privKey);

        this.key = dh1 + dh2 + dh3 + dh4;
        this.key = await crypto.hash(this.key);
        this.key = this.key.slice(0, 32);

        let associatedData = await crypto.decrypt(
            this.key,
            message.message,
            this.iv
        );
        console.log(associatedData);
        this.rootRatchetKey = this.key;
        if (
            helper.arrayBufferToBase64(associatedData) ==
            helper.arrayBufferToBase64(
                helper.appendBuffer(
                    message.identityKey,
                    this.myIdentityKey.pubKey
                )
            )
        ) {
            console.log("X3DH successful");
        }
    }

    async receive(message) {
        if (this.initialMessage) {
            return this.receiveInitialMessage(message);
        }
        this.currPublicKey = message.currPublicKey;
        this.resetRatchets();

        let currDecryptionKey;
        [this.recvRatchetKey, currDecryptionKey] = await crypto.KDF(
            this.currRatchetInput,
            this.recvRatchetKey,
            this.kdfInfo
        );
        let decryptedMessage = await crypto.decrypt(
            currDecryptionKey,
            message.message,
            this.iv
        );
        return Buffer.from(
            helper.arrayBufferToBase64(decryptedMessage),
            "base64"
        ).toString("utf8");
    }
}

module.exports = {
    Messenger,
};
