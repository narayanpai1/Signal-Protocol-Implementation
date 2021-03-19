class Messenger {
    constructor(userDetails) {
        for (prop in userDetails) {
            this[prop] = userDetails[prop];
        }
        initialMessage = true;
    }

    sendInitialMessage(message) {
        this.initialMessage = false;
    }

    send(message) {
        if (initialMessage) {
            return sendInitialMessage(message);
        }
    }

    receiveInitialMessage(message) {
        this.initialMessage = false;
    }

    receive(message) {
        if (initialMessage) {
            return receiveInitialMessage(message);
        }
    }
}
