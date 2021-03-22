let helper = require("./helper");
const crypto = require("./crypto");

class Messenger {
    constructor(userDetails, myDetails) {
        for (let prop in userDetails) {
            this[prop] = userDetails[prop];
            if (typeof this[prop] === "string") {
                this[prop] = helper.base64ToArrayBuffer(this[prop]);
            }
        }
        for (let prop in myDetails) {
            this[prop] = myDetails[prop];
        }
        this.initialMessage = true;
        console.log(this.myIdentityKey.pubKey, this.identityKey);
        this.associatedData = helper.appendBuffer(
            this.myIdentityKey.pubKey,
            this.identityKey
        );
        this.ephemeralKey = "";
        this.key = "";
        this.iv = new Uint8Array(16);
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

        let initialCipherMessage = await crypto.encrypt(
            this.key,
            this.associatedData,
            this.iv
        );

        console.log(this.key, initialCipherMessage);

        let rv = {
            identityKey: helper.arrayBufferToBase64(this.myIdentityKey.pubKey),
            ephemeralKey: helper.arrayBufferToBase64(this.ephemeralKey.pubKey),
            preKey: helper.arrayBufferToBase64(this.oneTimePreKey),
            message: helper.arrayBufferToBase64(initialCipherMessage),
        };
        return rv;
    }

    send(message) {
        return message;
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

        console.log(this.key);
        let associatedData = await crypto.decrypt(
            this.key,
            message.message,
            this.iv
        );

        if (
            helper.arrayBufferToBase64(associatedData) ===
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
        console.log("Received message", message);
    }
}

module.exports = {
    Messenger,
};
