# Signal Protocol Implementation

This repository contains a terminal-based chat application that uses parts of Signal Protocol for end-to-end encryption.

Specifically, it uses X3DH protocol for asynchronous key-exchange ensuring forward secrecy and the Double Ratchet Algorithm for break-in recovery and resilience.

Follow these steps to use the app

1. Install the dependencies
    ```
    npm install
    ```

2. Run the chat server.
    ```
    node server.js
    ```

    Whenever a client interacts with the server, it displays debug data including the user-metadata it stores.

3. Run the chat app
    ```
    node --no-warnings chat.js
    ```

    The app gives a clear set of steps the user has to follow to chat with any user.
    Firstly, it will require you to set up a username and then gives you a list of choices to perform everytime.

A screenshot of a sample run where two users chat with each other is shown in the following image.
![image](https://user-images.githubusercontent.com/43881774/139833132-e1339881-dffd-4e0d-8d13-21f467bc6340.png)
