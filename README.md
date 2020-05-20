# DoubleRatchet

Implementation of the <a href="https://www.signal.org/docs/specifications/doubleratchet/#external-functions">Double Ratchet</a> protocol in Swift. The cryptographic operations are provided by <a href="https://github.com/jedisct1/libsodium">libsodium</a> entirely.

## Installation
### SPM
`.package(url: "https://github.com/TICESoftware/DoubleRatchet.git", .upToNextMajor(from: "1.0.0"))`

In order to build the library it is necessary to link libsodium. The <a href="https://github.com/jedisct1/libsodium">official repository</a> includes scripts to build binaries for specific platforms.

`swift build -Xcc -I[header search path] -Xlinker -L[binary path]`

When using Xcode you can set the header search path manually to include the libsodium header files and link the static libsodium library.

### CodoaPods
`pod 'DoubleRatchet'`

This uses <a href="https://github.com/jedisct1/swift-sodium">`Sodium`</a> as a dependency which includes the pre-compiled libsodium library. No further setup necessary.

## Usage

Alice and Bob calculate a shared secret using a secure channel. After that one party can start the conversation as soon as she gets to know the public key of the other one.

```swift
import DoubleRatchet

let sharedSecret: Bytes = ...
let info = "DoubleRatchetExample"

let bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)

// Bob sends his public key to Alice using another channel
// sendToAlice(bob.publicKey)

let alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)

// Now the conversation begins
let message = "Hello, Bob!".bytes
let encryptedMessage = try alice.encrypt(plaintext: message)
let decryptedMessage = try bob.decrypt(message: encryptedMessage)

print(decryptedMessage.utf8String!) // Hello, Bob!
```
