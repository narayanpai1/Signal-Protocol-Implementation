let helper = require("./helper");
const crypto = require("./crypto");

class Messenger {
    constructor(userDetails, myDetails) {
        for (let prop in userDetails) {
            this[prop] = userDetails[prop];
            if (typeof this[prop] === "string") {
                this[prop] = helper.str2ab(this[prop]);
            }
        }
        for (let prop in myDetails) {
            this[prop] = myDetails[prop];
        }
        this.initialMessage = true;
        this.associatedData =
            helper.ab2str(this.myIdentityKey.pubKey) + this.identityKey;
        this.ephemeralKey = "";
        this.key = "";
        this.iv = new Uint8Array(16);
    }

    async sendInitialMessage(message) {
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
        // console.log(dh1, dh2, dh3, dh4);
        this.key = dh1 + dh2 + dh3 + dh4;
        this.key = await crypto.hash(this.key);
        this.key = this.key.slice(0, 32);
        // console.log("oooi", this.key);
        let messages = await crypto.encrypt(this.key, message, this.iv);
        // console.log(messages);
        let rv = {
            identityKey: helper.ab2str(this.myIdentityKey.pubKey),
            ephemeralKey: helper.ab2str(this.ephemeralKey.pubKey),
            preKey: helper.ab2str(this.oneTimePreKey),
            message: helper.ab2str(messages),
        };
        return rv;
    }

    send(message) {
        if (this.initialMessage) {
            return this.sendInitialMessage(message);
        }
        return message;
    }

    receiveInitialMessage(message) {
        this.initialMessage = false;
        console.log(message);
    }

    async receive(message) {
        if (this.initialMessage) {
            return this.receiveInitialMessage(message);
        }
        message = helper.toabObj(message);
        let otkey = this.myOneTimePreKeys.pop();
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
        // console.log(dh1, dh2, dh3, dh4);
        this.key = dh1 + dh2 + dh3 + dh4;
        this.key = await crypto.hash(this.key);
        this.key = this.key.slice(0, 32);
        let messages = await crypto.decrypt(this.key, message.message, this.iv);
        console.log("Decrypted", messages);
        const textDecoder = new TextDecoder("utf-8");
        console.log(textDecoder.decode(messages));
    }
}

module.exports = {
    Messenger,
};
