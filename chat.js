const crypto = require("./crypto");
const axios = require("axios");
const helper = require("./helper");
const messenger = require("./messenger");

let username, identityKey, preKey, signOfPreKey, oneTimePreKeys;
let messengers = {};

const readline = require("readline").createInterface({
    input: process.stdin,
    output: process.stdout,
});

const reader = readline[Symbol.asyncIterator]();

(async function initiate() {
    console.log("Enter username");
    username = await reader.next();
    identityKey = await crypto.createKeyPair();
    preKey = await crypto.createKeyPair();
    oneTimePreKeys = [];
    for (var i = 0; i < 5; i++) {
        oneTimePreKeys[i] = await crypto.createKeyPair();
    }
    console.log(identityKey.privKey);
    console.log(helper.ab2str(identityKey.privKey));
    console.log(helper.str2ab(helper.ab2str(identityKey.privKey)));
    signOfPreKey = await crypto.Ed25519Sign(identityKey.privKey, preKey.pubKey);

    try {
        let xx = await crypto.Ed25519Verify(
            identityKey.pubKey,
            preKey.pubKey,
            signOfPreKey
        );
        console.log(xx);
    } catch (e) {
        console.log(e);
        process.exit();
    }

    try {
        let res = await axios.post("http://localhost:3000/init", {
            username,
            details: {
                identityKey: helper.ab2str(identityKey.pubKey),
                preKey: helper.ab2str(preKey.pubKey),
                preKeySig: helper.ab2str(signOfPreKey),
                oneTimePrekey: oneTimePreKeys.map((x) =>
                    helper.ab2str(x.pubKey)
                ),
            },
        });
    } catch (e) {
        console.log(e.name);
    }

    let PROMPT = `Choose an option\n1. Get all the messages\n2. Send a message to someone\n3. Exit\n`;

    (async function loop() {
        console.log(PROMPT);
        let { value: opt } = await reader.next();
        if (opt == "1") {
            await getAllMessages();
        } else if (opt == "2") {
            await sendMessage();
        } else if (opt == "3") {
            process.exit();
        } else {
            console.log("Wrong Input");
        }
        loop();
    })();
})();

async function getAllMessages() {
    try {
        let res = await axios.post(
            "http://localhost:3000/getAllUnreadMessages",
            {
                username,
            }
        );
        for (m in res.body.messages) {
            if (!messengers[m.username]) {
                messengers[m.username] = new Messenger();
            }
            await messengers[m.username].receive(m.body);
        }
    } catch (e) {
        console.log(e.name);
    }
}

async function sendMessage() {
    console.log("Whom do you want to text?");
    let { value: toUser } = await reader.next();
    console.log("Enter the message");
    let { value: rawMessage } = await reader.next();

    if (!messengers[toUser]) {
        try {
            let res = await axios.post("http://localhost:3000/getDetails", {
                username: toUser,
            });
            messengers[toUser] = new Messenger(res.body);
        } catch (e) {
            console.log(e.name);
            return;
        }
    }

    let encryptedMessage = await messengers[toUser].send(rawMessage);

    try {
        await axios.post("http://localhost:3000/sendMessage", {
            username,
            toUser,
            message: encryptedMessage,
        });
        console.log("Sent!");
    } catch (e) {
        console.log(e.name);
        return;
    }
}
