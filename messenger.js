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
        console.log("DH Ratchet Initialized");
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
        console.log("Common keys established");

        let initialCipherMessage = await crypto.encrypt(
            this.key,
            this.associatedData,
            this.iv
        );

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
            currPublicKey: helper.arrayBufferToBase64(
                this.myCurrRatchetKey.pubKey
            ),
            message: helper.arrayBufferToBase64(cipherMessage),
            rawMessage: message,
        };
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

        console.log("Common keys established");

        this.rootRatchetKey = this.key;
        console.log("X3DH successful");
    }

    async receive(message) {
        if (this.initialMessage) {
            return this.receiveInitialMessage(message);
        }
        let mm = message.rawMessage;
        message = helper.toArrayBufferObj(message);
        this.currPublicKey = message.currPublicKey;
        await this.resetRatchets();
        console.log("Ratchets reset");

        [this.recvRatchetKey, this.rootRatchetKey] = await crypto.KDF(
            this.currRatchetInput,
            this.rootRatchetKey,
            this.kdfInfo
        );
        [this.sendRatchetKey, this.rootRatchetKey] = await crypto.KDF(
            this.currRatchetInput,
            this.rootRatchetKey,
            this.kdfInfo
        );

        let currDecryptionKey;
        [this.recvRatchetKey, currDecryptionKey] = await crypto.KDF(
            this.currRatchetInput,
            this.recvRatchetKey,
            this.kdfInfo
        );
        return mm;
    }
}

module.exports = {
    Messenger,
};
