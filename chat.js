const crypto = require("./crypto");
const axios = require("axios");
const helper = require("./helper");
const messenger = require("./messenger");

let messengers = {};
let myDetails = {};

const readline = require("readline").createInterface({
    input: process.stdin,
    output: process.stdout,
});

const reader = readline[Symbol.asyncIterator]();

(async function initiate() {
    console.log("Enter username");
    let { value: userr } = await reader.next();
    myDetails.myUsername = userr;
    myDetails.myIdentityKey = await crypto.createKeyPair();
    myDetails.myPreKey = await crypto.createKeyPair();
    myDetails.myOneTimePreKeys = [];
    for (var i = 0; i < 5; i++) {
        myDetails.myOneTimePreKeys[i] = await crypto.createKeyPair();
    }
    myDetails.mySignOfPreKey = await crypto.Ed25519Sign(
        myDetails.myIdentityKey.privKey,
        myDetails.myPreKey.pubKey
    );

    try {
        let xx = await crypto.Ed25519Verify(
            myDetails.myIdentityKey.pubKey,
            myDetails.myPreKey.pubKey,
            myDetails.mySignOfPreKey
        );
        console.log(xx);
    } catch (e) {
        console.log(e);
        process.exit();
    }

    try {
        let res = await axios.post("http://localhost:3000/init", {
            username: myDetails.myUsername,
            details: {
                identityKey: helper.ab2str(myDetails.myIdentityKey.pubKey),
                preKey: helper.ab2str(myDetails.myPreKey.pubKey),
                preKeySig: helper.ab2str(myDetails.mySignOfPreKey),
                oneTimePreKey: myDetails.myOneTimePreKeys.map((x) =>
                    helper.ab2str(x.pubKey)
                ),
            },
        });
    } catch (e) {
        console.log(e);
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
                username: myDetails.myUsername,
            }
        );
        for (m in res.data.messages) {
            let user = res.data.messages[m];
            if (!messengers[user.username]) {
                messengers[user.username] = new messenger.Messenger(
                    {},
                    myDetails
                );
            }
            await messengers[(user, myDetails.myUsername)].receive(
                user.message
            );
        }
    } catch (e) {
        console.log(e);
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
            messengers[toUser] = new messenger.Messenger(res.data, myDetails);
        } catch (e) {
            console.log(e);
            return;
        }
    }

    let encryptedMessage = await messengers[toUser].send(rawMessage);

    try {
        await axios.post("http://localhost:3000/sendMessage", {
            username: myDetails.myUsername,
            toUser,
            message: encryptedMessage,
        });
        console.log("Sent!");
    } catch (e) {
        console.log(e);
        return;
    }
}
