# Cryptography Playground — Desktop App (Electron)

This is a desktop app version. It works fully offline and avoids browser restrictions on Web Crypto APIs.

## Run the app

1) Install Node.js (16+ recommended): https://nodejs.org/
2) Open a terminal in this folder and run:
```
npm install
npm start
```
The Electron window will open with your app.

## Build notes
- DES and ElGamal are **educational demos** (not secure).
- RSA, ECDH (Diffie–Hellman), and SHA use the platform's Web Crypto implementation in Chromium.
