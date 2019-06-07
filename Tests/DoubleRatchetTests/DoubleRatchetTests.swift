//
//  Copyright © 2019 Anbion. All rights reserved.
//

import XCTest
import Sodium
@testable import DoubleRatchet

final class DoubleRatchetTests: XCTestCase {

    let sodium = Sodium()
    let sharedSecret = Sodium().utils.hex2bin("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF", ignore: " ")!

    var alice: DoubleRatchet!
    var bob: DoubleRatchet!
    let info = "DoubleRatchetTest"

    override func setUp() {
        super.setUp()

        bob = try! DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
        alice = try! DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
    }

    func testRatchetSteps() {
        do {
            let bobPublicKeySnapshot = bob.publicKey

            let message = "aliceToBob".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message)
            let decryptedMessage = try bob.decrypt(message: encryptedMessage)
            XCTAssertEqual(message, decryptedMessage)
            XCTAssertNotEqual(bob.publicKey, bobPublicKeySnapshot)

            let alicePublicKeySnapshot = alice.publicKey

            let response = "bobToAlice".bytes
            let encryptedResponse = try bob.encrypt(plaintext: response)
            let decryptedResponse = try alice.decrypt(message: encryptedResponse)
            XCTAssertEqual(response, decryptedResponse)
            XCTAssertNotEqual(alice.publicKey, alicePublicKeySnapshot)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testUnidirectionalConversation() {
        do {
            let alicePublicKeySnapshot = alice.publicKey

            for _ in 0...1 {
                let message = "aliceToBob".bytes
                let encryptedMessage = try alice.encrypt(plaintext: message)
                let decryptedMessage = try bob.decrypt(message: encryptedMessage)
                XCTAssertEqual(message, decryptedMessage)
            }

            XCTAssertEqual(alice.publicKey, alicePublicKeySnapshot)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testLostMessages() {
        do {
            var delayedMessages: [Message] = []
            for i in 0...2 {
                let message = "aliceToBob\(i)".bytes
                let encryptedMessage = try alice.encrypt(plaintext: message)
                delayedMessages.append(encryptedMessage)
            }

            for i in (0...2).reversed() {
                let decryptedMessage = try bob.decrypt(message: delayedMessages[i])
                XCTAssertEqual(decryptedMessage, "aliceToBob\(i)".bytes)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testLostMessagesAndRatchetStep() {
        do {
            let message = "aliceToBob".bytes

            for _ in 0...1 {
                let encryptedMessage = try alice.encrypt(plaintext: message)
                _ = try bob.decrypt(message: encryptedMessage)
            }

            var delayedMessages: [Message] = []
            for i in 0...1 {
                if i == 1 {
                    // Ratchet step
                    let message = try bob.encrypt(plaintext: message)
                    _ = try alice.decrypt(message: message)
                }
                let message = "aliceToBob\(i)".bytes
                let encryptedMessage = try alice.encrypt(plaintext: message)
                delayedMessages.append(encryptedMessage)
            }

            let successfulMessage = "aliceToBob2".bytes
            let successfulEncryptedRatchetMessage = try alice.encrypt(plaintext: successfulMessage)
            let successfulPlaintext = try bob.decrypt(message: successfulEncryptedRatchetMessage)
            XCTAssertEqual(successfulPlaintext, successfulMessage)

            for i in (0...1).reversed() {
                let decryptedMessage = try bob.decrypt(message: delayedMessages[i])
                XCTAssertEqual(decryptedMessage, "aliceToBob\(i)".bytes)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testExceedMaxSkipMessages() {
        do {
            bob = try! DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)
            alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)

            for _ in 0...1 {
                _ = try alice.encrypt(plaintext: "Message".bytes)
            }

            let encryptedMessage = try alice.encrypt(plaintext: "Message".bytes)
            _ = try bob.decrypt(message: encryptedMessage)
            XCTFail()
        } catch {
            guard case DRError.exceedMaxSkip = error else {
                XCTFail()
                return
            }
        }
    }

    func testExceedMaxCacheMessageKeys() {
        bob = try! DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try! DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        var delayedMessages: [Message] = []

        do {
            for i in 0...2 {
                let message = "aliceToBob\(i)"
                let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
                delayedMessages.append(encryptedMessage)
            }

            for i in (1...2).reversed() {
                let plaintext = try bob.decrypt(message: delayedMessages[i])
                XCTAssertEqual(plaintext, "aliceToBob\(i)".bytes)
            }
        } catch {
            XCTFail(error.localizedDescription)
        }

        do {
            _ = try bob.decrypt(message: delayedMessages[0])
            XCTFail()
        } catch {
            guard case DRError.discardOldMessage = error else {
                XCTFail(error.localizedDescription)
                return
            }
        }
    }

    func testEncryptAssociatedData() {
        do {
            let message = "aliceToBob".bytes
            let associatedData = "AD".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message, associatedData: associatedData)
            let decryptedMessage = try bob.decrypt(message: encryptedMessage, associatedData: associatedData)
            XCTAssertEqual(message, decryptedMessage)

        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testReinitializeSession() {
        bob = try! DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try! DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        do {
            let message = "aliceToBob"
            let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
            let plaintext = try bob.decrypt(message: encryptedMessage)
            XCTAssertEqual(plaintext.utf8String!, message)
        } catch {
            XCTFail(error.localizedDescription)
        }

        bob = DoubleRatchet(sessionState: bob.sessionState)
        alice = DoubleRatchet(sessionState: alice.sessionState)

        do {
            let messageAliceToBob = "aliceToBob"
            let encryptedMessageAliceToBob = try alice.encrypt(plaintext: messageAliceToBob.bytes)
            let plaintextAliceToBob = try bob.decrypt(message: encryptedMessageAliceToBob)
            XCTAssertEqual(plaintextAliceToBob.utf8String!, messageAliceToBob)

            let messageBobToAlice = "bobToAlice"
            let encryptedMessageBobToAlice = try bob.encrypt(plaintext: messageBobToAlice.bytes)
            let plaintextBobToAlice = try alice.decrypt(message: encryptedMessageBobToAlice)
            XCTAssertEqual(plaintextBobToAlice.utf8String!, messageBobToAlice)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    static var allTests = [
        ("testRatchetSteps", testRatchetSteps),
        ("testUnidirectionalConversation", testUnidirectionalConversation),
        ("testLostMessages", testLostMessages),
        ("testLostMessagesAndRatchetStep", testLostMessagesAndRatchetStep),
        ("testExceedMaxSkipMessages", testExceedMaxSkipMessages),
        ("testExceedMaxCacheMessageKeys", testExceedMaxCacheMessageKeys),
        ("testEncryptAssociatedData", testEncryptAssociatedData),
        ("testReinitializeSession", testReinitializeSession),
    ]
}
