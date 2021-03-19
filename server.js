const express = require("express");
const app = express();

const port = 3000;

app.use(express.json());

let Users = {}; // object containing details of different users with username as the key
let UnsentMessages = {}; // object containing messages that are not yet sent for different users.

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
    Users[req.body.username] = req.body.details;
    console.log(req.body.details);
    res.send("Saved!");
});

/*
A user sends the username of the person he wants to connect to
{username}

and receives the person's
Identity key IKB
Signed prekey SPKB
Prekey signature Sig(IKB, Encode(SPKB))
One of the one-time prekeys (OPKBi)
*/
app.post("/getDetails", (req, res) => {
    let user = {
        ...Users[req.body.username],
        oneTimePreKey: Users[req.body.username].oneTimePrekeys.pop(),
    };
    res.json(user);
});

/*
User A initiates the chat with user B by 
Username of B
Identity key IKA
Ephemeral key EKA
Identifiers stating which of B's prekeys A used
An initial ciphertext encrypted with some AEAD encryption scheme [4] using AD as associated data and using an encryption key which is either SK or the output from some cryptographic PRF keyed by SK.
*/
app.post("/initiate", (req, res) => {});

app.post("/sendMessage", (req, res) => {});

/*
The user sends only the username
*/
app.post("/getAllUnreadMessages", (req, res) => {});

app.listen(port, () =>
    console.log(`Hello world app listening on port ${port}!`)
);
