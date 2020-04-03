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

    func testRatchetSteps() throws {
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
    }

    func testUnidirectionalConversation() throws {
        let alicePublicKeySnapshot = alice.publicKey

        for _ in 0...1 {
            let message = "aliceToBob".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message)
            let decryptedMessage = try bob.decrypt(message: encryptedMessage)
            XCTAssertEqual(message, decryptedMessage)
        }

        XCTAssertEqual(alice.publicKey, alicePublicKeySnapshot)
    }

    func testLostMessages() throws {
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
    }

    func testLostMessagesAndRatchetStep() throws {
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
    }

    func testExceedMaxSkipMessages() throws {
            bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)
            alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)

            for _ in 0...1 {
                _ = try alice.encrypt(plaintext: "Message".bytes)
            }

            let encryptedMessage = try alice.encrypt(plaintext: "Message".bytes)

        do {
            _ = try bob.decrypt(message: encryptedMessage)
            XCTFail()
        } catch {
            guard case DRError.exceedMaxSkip = error else {
                XCTFail()
                return
            }
        }
    }

    func testExceedMaxCacheMessageKeys() throws {
        bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        var delayedMessages: [Message] = []

        for i in 0...2 {
            let message = "aliceToBob\(i)"
            let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
            delayedMessages.append(encryptedMessage)
        }

        for i in (1...2).reversed() {
            let plaintext = try bob.decrypt(message: delayedMessages[i])
            XCTAssertEqual(plaintext, "aliceToBob\(i)".bytes)
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

    func testEncryptAssociatedData() throws {
        let message = "aliceToBob".bytes
        let associatedData = "AD".bytes
        let encryptedMessage = try alice.encrypt(plaintext: message, associatedData: associatedData)
        let decryptedMessage = try bob.decrypt(message: encryptedMessage, associatedData: associatedData)
        XCTAssertEqual(message, decryptedMessage)
    }

    func testReinitializeSession() throws {
        bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        let message = "aliceToBob"
        let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
        let plaintext = try bob.decrypt(message: encryptedMessage)
        XCTAssertEqual(plaintext.utf8String!, message)

        bob = DoubleRatchet(sessionState: bob.sessionState)
        alice = DoubleRatchet(sessionState: alice.sessionState)

        let messageAliceToBob = "aliceToBob"
        let encryptedMessageAliceToBob = try alice.encrypt(plaintext: messageAliceToBob.bytes)
        let plaintextAliceToBob = try bob.decrypt(message: encryptedMessageAliceToBob)
        XCTAssertEqual(plaintextAliceToBob.utf8String!, messageAliceToBob)

        let messageBobToAlice = "bobToAlice"
        let encryptedMessageBobToAlice = try bob.encrypt(plaintext: messageBobToAlice.bytes)
        let plaintextBobToAlice = try alice.decrypt(message: encryptedMessageBobToAlice)
        XCTAssertEqual(plaintextBobToAlice.utf8String!, messageBobToAlice)
    }
    
    func testMessageHeaderEncoding() throws {
        let pubKey = Sodium().utils.hex2bin("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f932544443")!
        let header = Header(publicKey: pubKey, numberOfMessagesInPreviousSendingChain: 123456789, messageNumber: 987654321)
        
        let headerBytesAre = try header.bytes()
        let headerBytesShouldBe = Sodium().utils.hex2bin("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f93254444300000000499602d2000000024cb016ea")!
        XCTAssertEqual(headerBytesAre, headerBytesShouldBe)
    }

    func testGenerateKeyPairAndSharedSecret() throws {
        let sodium = Sodium()

        let keyPair = sodium.keyExchange.keyPair()!
        let keyPairData = try JSONEncoder().encode(keyPair)

        let sharedSecret = sodium.randomBytes.buf(length: 32)!

        print(String(data: keyPairData, encoding: .utf8)!)
        print(sodium.utils.bin2hex(sharedSecret)!)
    }

    func testInitiateConversation() throws {
        let ownKeyPairString =
"""
{"secretKey":"e0f8e1fb1e2a33e63d4e67a1488dd2c802d79d8c4ab2fc2684ab2cb4175b55b2","publicKey":"9258fd6cf6ee77f0518d91265438a02a60c71a449a56b9ce4ceec0015b17e35a"}
"""
        let otherKeyPairString =
"""
{"secretKey":"326873752B2547AEB5C2A652FEDAC5EBFD652E0F944F0AF1E66C640985A627A9","publicKey":"D3A6E65CD63116F38C361F0CC857216E792552D740C79F603D23262C6DC20F56"}
"""
        let sharedSecretString =
"""
1208db7dad21875cf6ba8c96f8fbfae00fb4c06ab3cbd1597b635c3989b1a67a
"""
        let sodium = Sodium()

        let decoder = JSONDecoder()
        let ownKeyPair = try decoder.decode(KeyPair.self, from: ownKeyPairString.data(using: .utf8)!)
        let otherKeyPair = try decoder.decode(KeyPair.self, from: otherKeyPairString.data(using: .utf8)!)
        let sharedSecret = sodium.utils.hex2bin(sharedSecretString)!

        let doubleRatchet = try DoubleRatchet(keyPair: ownKeyPair, remotePublicKey: otherKeyPair.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: "Info")

        let firstMessage = "firstMessage".bytes
        let encryptedFirstMessage = try doubleRatchet.encrypt(plaintext: firstMessage)

        let encryptedFirstMessageData = try JSONEncoder().encode(encryptedFirstMessage)

        print(String(data: encryptedFirstMessageData, encoding: .utf8)!)
    }

    func testProcessFirstMessage() throws {
        let ownKeyPairString =
"""
{"secretKey":"e0f8e1fb1e2a33e63d4e67a1488dd2c802d79d8c4ab2fc2684ab2cb4175b55b2","publicKey":"9258fd6cf6ee77f0518d91265438a02a60c71a449a56b9ce4ceec0015b17e35a"}
"""
        let sharedSecretString =
"""
1208db7dad21875cf6ba8c96f8fbfae00fb4c06ab3cbd1597b635c3989b1a67a
"""
        let firstEncryptedMessageString =
"""
{"header":{"publicKey":"DB9CECF895EE20BF15AE7089949CB3FE3DFFCD9C5781D55345FB6584D00A680A","numberOfMessagesInPreviousSendingChain":0,"messageNumber":0},"cipher":"10571EB26742847AA15F6F9314B561571C088693BACC0C78579296FDBA9119376DA67700AD7D117684CB380628EDF77973E7CF7A"}
"""

        let sodium = Sodium()

        let decoder = JSONDecoder()
        let ownKeyPair = try decoder.decode(KeyPair.self, from: ownKeyPairString.data(using: .utf8)!)
        let sharedSecret = sodium.utils.hex2bin(sharedSecretString)!
        let firstEncryptedMessage = try decoder.decode(Message.self, from: firstEncryptedMessageString.data(using: .utf8)!)

        let doubleRatchet = try DoubleRatchet(keyPair: ownKeyPair, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: "Info")

        let decryptedMessage = try doubleRatchet.decrypt(message: firstEncryptedMessage)

        XCTAssertEqual(decryptedMessage.utf8String!, "firstMessage")
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
        ("testMessageHeaderEncoding", testMessageHeaderEncoding),
    ]
}

extension KeyPair: Codable {
    private enum CodingKeys: String, CodingKey {
        case secretKey
        case publicKey
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        try container.encode(sodium.utils.bin2hex(secretKey)!, forKey: .secretKey)
        try container.encode(sodium.utils.bin2hex(publicKey)!, forKey: .publicKey)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        let secretKey = try container.decode(String.self, forKey: .secretKey)
        let publicKey = try container.decode(String.self, forKey: .publicKey)

        self.init(publicKey: sodium.utils.hex2bin(publicKey)!, secretKey: sodium.utils.hex2bin(secretKey)!)
    }
}

extension Header: Codable {
    private enum CodingKeys: String, CodingKey {
        case publicKey
        case numberOfMessagesInPreviousSendingChain
        case messageNumber
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        try container.encode(sodium.utils.bin2hex(publicKey)!, forKey: .publicKey)
        try container.encode(numberOfMessagesInPreviousSendingChain, forKey: .numberOfMessagesInPreviousSendingChain)
        try container.encode(messageNumber, forKey: .messageNumber)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        let publicKey = try container.decode(String.self, forKey: .publicKey)
        let numberOfMessagesInPreviousSendingChain = try container.decode(Int.self, forKey: .numberOfMessagesInPreviousSendingChain)
        let messageNumber = try container.decode(Int.self, forKey: .messageNumber)

        self.init(publicKey: sodium.utils.hex2bin(publicKey)!, numberOfMessagesInPreviousSendingChain: numberOfMessagesInPreviousSendingChain, messageNumber: messageNumber)
    }
}

extension Message: Codable {
    private enum CodingKeys: String, CodingKey {
        case header
        case cipher
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        try container.encode(header, forKey: .header)
        try container.encode(sodium.utils.bin2hex(cipher)!, forKey: .cipher)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let sodium = Sodium()
        let header = try container.decode(Header.self, forKey: .header)
        let cipher = try container.decode(String.self, forKey: .cipher)

        self.init(header: header, cipher: sodium.utils.hex2bin(cipher)!)
    }
}
