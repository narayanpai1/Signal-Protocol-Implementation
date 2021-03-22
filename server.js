const express = require("express");
const app = express();

const port = 3000;

app.use(express.json());

let users = {}; // object containing details of different users with username as the key
let unsentMessages = {}; // object containing messages that are not yet sent for different users.

/*
A user sends his/her
Username
Identity key IKB
Signed prekey SPKB
Prekey signature Sig(IKB, Encode(SPKB))
A set of one-time prekeys (OPKB1, OPKB2, OPKB3, ...)
{
    username:,
    details:{identityKey, preKey, preKeySig, oneTimePreKey[] }
}

Receives a confirmation
*/
app.post("/init", (req, res) => {
    users[req.body.username] = req.body.details;
    console.log(users);
    console.log(req.body.details);
    res.send("Saved!");
});

/*
A user sends the username of the person he wants to connect to
{username}

and receives the person's{identityKey, preKey, preKeySig, oneTimePreKey}
Identity key IKB
Signed prekey SPKB
Prekey signature Sig(IKB, Encode(SPKB))
One of the one-time prekeys (OPKBi)
*/
app.post("/getDetails", (req, res) => {
    console.log(req.body);
    let user = {
        ...users[req.body.username],
        oneTimePreKey: users[req.body.username].oneTimePreKey.pop(),
    };
    res.json(user);
});

/*
{username:, toUser:, message:}

If User A is initiating the chat with user B by 
Username of B
Identity key IKA
Ephemeral key EKA
Identifiers stating which of B's prekeys A used
An initial ciphertext encrypted with some AEAD encryption scheme [4] using AD as associated data and using an encryption key which is either SK or the output from some cryptographic PRF keyed by SK.
*/
app.post("/sendMessage", (req, res) => {
    let { body } = req;
    !unsentMessages[body.toUser] && (unsentMessages[body.toUser] = []);
    console.log(body);

    unsentMessages[body.toUser].push({
        username: body.username,
        message: body.message,
    });
    res.json({ done: 200 });
});

/*
{username}
The user sends only the username

returns {messages:[{username:, message:}]}
*/
app.post("/getAllUnreadMessages", (req, res) => {
    let user = req.body.username;
    !unsentMessages[user] && (unsentMessages[user] = []);

    res.json({ messages: unsentMessages[user] });
    unsentMessages[user] = [];
});

app.listen(port, () =>
    console.log(`Hello world app listening on port ${port}!`)
);
