# DoubleRatchet

Implementation of the <a href="https://www.signal.org/docs/specifications/doubleratchet/#external-functions">Double Ratchet</a> protocol in Swift. The cryptographic operations are provided by <a href="https://github.com/jedisct1/libsodium">libsodium</a> entirely.

# Usage

Alice and Bob calculate a shared secret using a secure channel. After that one party can start the conversation as soon as she gets to know the public key of the other one.

```swift
import DoubleRatchet

let sharedSecret: Bytes = ...
let info = "DoubleRatchetExample"

let bob = try DoubleRatchet(remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)

// Bob sends his public key to Alice using another channel
// sendToAlice(bob.publicKey)

let alice = try DoubleRatchet(remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)

// Now the conversation begins
let message = "Hello, Bob!".bytes
let encryptedMessage = try alice.encrypt(plaintext: message)
let decryptedMessage = try bob.decrypt(message: encryptedMessage)

print(decryptedMessage.utf8String!) // Hello, Bob!
```
