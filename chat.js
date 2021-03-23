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

readline.on("SIGINT", () => {
    process.exit();
});

const reader = readline[Symbol.asyncIterator]();

(async function initiate() {
    console.log("Enter username");
    let { value: userr } = await reader.next();
    myDetails.myUsername = userr;
    myDetails.myIdentityKey = await crypto.createKeyPair();
    myDetails.myPreKey = await crypto.createKeyPair();
    myDetails.myCurrRatchetKey = await crypto.createKeyPair();
    myDetails.myOneTimePreKeys = [];
    for (var i = 0; i < 5; i++) {
        myDetails.myOneTimePreKeys[i] = await crypto.createKeyPair();
    }
    myDetails.mySignOfPreKey = await crypto.Ed25519Sign(
        myDetails.myIdentityKey.privKey,
        myDetails.myPreKey.pubKey
    );

    try {
        await crypto.Ed25519Verify(
            myDetails.myIdentityKey.pubKey,
            myDetails.myPreKey.pubKey,
            myDetails.mySignOfPreKey
        );
    } catch (e) {
        console.log(e);
        process.exit();
    }

    try {
        let res = await axios.post("http://localhost:3000/init", {
            username: myDetails.myUsername,
            details: {
                identityKey: helper.arrayBufferToBase64(
                    myDetails.myIdentityKey.pubKey
                ),
                preKey: helper.arrayBufferToBase64(myDetails.myPreKey.pubKey),
                preKeySig: helper.arrayBufferToBase64(myDetails.mySignOfPreKey),
                oneTimePreKey: myDetails.myOneTimePreKeys.map((x) =>
                    helper.arrayBufferToBase64(x.pubKey)
                ),
                currPublicKey: helper.arrayBufferToBase64(
                    myDetails.myCurrRatchetKey.pubKey
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
            let messageObj = res.data.messages[m];
            if (!messengers[messageObj.username]) {
                messengers[messageObj.username] = new messenger.Messenger(
                    messageObj.message,
                    myDetails
                );
            }
            let rawMessage = await messengers[messageObj.username].receive(
                messageObj.message
            );
            console.log(messageObj.username, "sends", rawMessage);
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
            // Get the details(public keys) of the user from the server
            let res = await axios.post("http://localhost:3000/getDetails", {
                username: toUser,
            });
            messengers[toUser] = await new messenger.Messenger(
                res.data,
                myDetails
            );
            let initialMessage = await messengers[toUser].sendInitialMessage();

            // send the initial message containing the Extended Triple Diffie Hellman parameters
            await axios.post("http://localhost:3000/sendMessage", {
                username: myDetails.myUsername,
                toUser,
                message: initialMessage,
            });
            console.log("Sent!");
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
