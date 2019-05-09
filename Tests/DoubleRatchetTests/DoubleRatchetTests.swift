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

        bob = try! DoubleRatchet(remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
        alice = try! DoubleRatchet(remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
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
            let encryptedMessage = try alice.encrypt(plaintext: message)
            _ = try bob.decrypt(message: encryptedMessage)

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
            bob = try! DoubleRatchet(remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)
            alice = try DoubleRatchet(remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)

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
        bob = try! DoubleRatchet(remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try! DoubleRatchet(remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        var delayedMessages: [Message] = []

        do {
            for i in 0...2 {
                let message = "aliceToBob\(i)"
                let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
                delayedMessages.append(encryptedMessage)
            }

            for i in (0...1).reversed() {
                let plaintext = try bob.decrypt(message: delayedMessages[i])
                XCTAssertEqual(plaintext, "aliceToBob\(i)".bytes)
            }
        } catch {
            XCTFail()
        }

        do {
            _ = try bob.decrypt(message: delayedMessages[0])
            XCTFail()
        } catch {
            guard case DRError.decryptionFailed = error else {
                XCTFail()
                return
            }
        }
    }

    static var allTests = [
        ("testRatchetSteps", testRatchetSteps),
        ("testUnidirectionalConversation", testUnidirectionalConversation),
        ("testLostMessages", testLostMessages),
        ("testLostMessagesAndRatchetStep", testLostMessagesAndRatchetStep),
        ("testExceedMaxSkipMessages", testExceedMaxSkipMessages),
        ("testExceedMaxCacheMessageKeys", testExceedMaxCacheMessageKeys),
    ]
}
