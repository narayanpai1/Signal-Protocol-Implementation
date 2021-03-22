function arrayBufferToBase64(buf) {
    return Buffer.from(
        String.fromCharCode.apply(null, new Uint16Array(buf)),
        "utf8"
    ).toString("base64");
}

function base64ToArrayBuffer(str) {
    str = Buffer.from(str, "base64").toString("utf8");
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return bufView.buffer;
}

function toBase64Obj(bufObj) {
    for (let key in bufObj) {
        if (typeof bufObj[key] === "object") {
            bufObj[key] = arrayBufferToBase64(bufObj[key]);
        }
    }
    return bufObj;
}
function toArrayBufferObj(bufObj) {
    for (let key in bufObj) {
        if (typeof bufObj[key] === "string") {
            bufObj[key] = base64ToArrayBuffer(bufObj[key]);
        }
    }
    return bufObj;
}

function appendBuffer(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}

module.exports = {
    arrayBufferToBase64: arrayBufferToBase64,
    base64ToArrayBuffer: base64ToArrayBuffer,
    toBase64Obj: toBase64Obj,
    toArrayBufferObj: toArrayBufferObj,
    appendBuffer,
};
