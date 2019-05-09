import Sodium
import HKDF

public class DoubleRatchet {
    let sodium = Sodium()

    let maxSkip: Int
    let info: String

    var rootChain: RootChain
    var sendingChain: MessageChain
    var receivingChain: MessageChain

    var sentMessageNumber: Int
    var receivedMessageNumber: Int
    var previousSendingChainLength: Int
    var skippedMessageKeys: [MessageIndex: Bytes]

    struct MessageIndex: Hashable {
        let publicKey: KeyExchange.PublicKey
        let messageNumber: Int
    }

    init(remotePublicKey: KeyExchange.PublicKey?, sharedSecret: Bytes, maxSkip: Int, info: String) throws {
        self.maxSkip = maxSkip
        self.info = info

        guard let keyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }

        self.rootChain = RootChain(dhRatchetKeyPair: keyPair, rootKey: sharedSecret)
        self.sendingChain = MessageChain(chainKey: [])
        self.receivingChain = MessageChain(chainKey: [])

        self.sentMessageNumber = 0
        self.receivedMessageNumber = 0
        self.previousSendingChainLength = 0
        self.skippedMessageKeys = [:]

        if let remotePublicKey = remotePublicKey {
            try ratchetStepSendingSide(publicKey: remotePublicKey)
        }
    }

    func encrypt(message: Bytes) throws -> Message {
        let messageKey = try sendingChain.nextMessageKey()
        let header = Header(publicKey: rootChain.currentPublicKey, numberOfMessagesInPreviousSendingChain: previousSendingChainLength, messageNumber: sentMessageNumber)
        sentMessageNumber += 1

        let headerData = try header.bytes()
        guard let cipher: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: messageKey, additionalData: headerData) else {
            throw DRError.encryptionFailed
        }
        return Message(header: header, cipher: cipher)
    }

    func decrypt(message: Message) throws -> Bytes {
        // Check for skipped messages
        if let plaintext = try decryptSkippedMessage(message) {
            return plaintext
        }

        // Check if ratchet step should be performed
        if message.header.publicKey != rootChain.currentPublicKey {
            try skipReceivedMessages(until: message.header.numberOfMessagesInPreviousSendingChain)
            try doubleRatchetStep(publicKey: message.header.publicKey)
        }

        try skipReceivedMessages(until: message.header.messageNumber)

        let messageKey = try receivingChain.nextMessageKey()
        let plaintext = try decrypt(message: message, key: messageKey)
        receivedMessageNumber += 1
        return plaintext
    }

    private func decryptSkippedMessage(_ message: Message) throws -> Bytes? {
        let skippedMessageIndex = MessageIndex(publicKey: message.header.publicKey, messageNumber: message.header.messageNumber)
        guard let messageKey = skippedMessageKeys[skippedMessageIndex] else { return nil }

        let plaintext = try decrypt(message: message, key: messageKey)
        skippedMessageKeys[skippedMessageIndex] = nil
        return plaintext
    }

    private func decrypt(message: Message, key: Bytes) throws -> Bytes {
        let headerData = try message.header.bytes()
        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: message.cipher, secretKey: key, additionalData: headerData) else {
            throw DRError.decryptionFailed
        }
        return plaintext
    }

    private func skipReceivedMessages(until nextMessageNumber: Int) throws {
        guard nextMessageNumber - receivedMessageNumber <= maxSkip else {
            throw DRError.exceedMaxSkip
        }

        while receivedMessageNumber < nextMessageNumber {
            let skippedMessageKey = try receivingChain.nextMessageKey()
            let skippedMessageIndex = MessageIndex(publicKey: rootChain.currentPublicKey, messageNumber: receivedMessageNumber)
            skippedMessageKeys[skippedMessageIndex] = skippedMessageKey
            receivedMessageNumber += 1
        }
    }

    private func ratchetStepSendingSide(publicKey: KeyExchange.PublicKey) throws {
        let (newRootKey, newSendingChainKey) = try deriveChainKeys(rootKey: rootChain.rootKey, info: info, keyPair: rootChain.dhRatchetKeyPair, remotePublicKey: publicKey)
        rootChain.rootKey = newRootKey
        sendingChain.chainKey = newSendingChainKey
    }

    private func ratchetStepReceivingSide(publicKey: KeyExchange.PublicKey) throws {
        let (newRootKey, newReceivingChainKey) = try deriveChainKeys(rootKey: rootChain.rootKey, info: info, keyPair: rootChain.dhRatchetKeyPair, remotePublicKey: publicKey)
        rootChain.rootKey = newRootKey
        receivingChain.chainKey = newReceivingChainKey
    }

    private func doubleRatchetStep(publicKey: KeyExchange.PublicKey) throws {
        previousSendingChainLength = receivedMessageNumber
        receivedMessageNumber = 0
        sentMessageNumber = 0

        try ratchetStepReceivingSide(publicKey: publicKey)

        let newKeyPair = try generateDHKeyPair()
        rootChain.dhRatchetKeyPair = newKeyPair

        try ratchetStepSendingSide(publicKey: publicKey)
    }

    // GENERATE_DH()
    private func generateDHKeyPair() throws -> KeyExchange.KeyPair {
        guard let keyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }
        return keyPair
    }

    // DH(dh_pair, dh_pub)
    private func dh(keyPair: KeyExchange.KeyPair, publicKey: KeyExchange.PublicKey) throws -> Bytes {
        guard let dh = sodium.keyExchange.sessionKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, otherPublicKey: publicKey, side: .CLIENT) else {
            throw DRError.dhKeyExchangeFailed
        }
        return dh.rx
    }

    // KDF_RK(rk, dh_out)
    private func deriveFromRootKDF(rootKey: Bytes, dhOut: Bytes, info: String) throws -> (rootKey: Bytes, chainKey: Bytes) {
        let derivedKey = try deriveHKDFKey(ikm: dhOut, salt: rootKey, info: info, L: 64)
        return (rootKey: Bytes(derivedKey[..<32]), chainKey: Bytes(derivedKey[32...]))
    }

    private func deriveChainKeys(rootKey: Bytes, info: String, keyPair: KeyExchange.KeyPair, remotePublicKey: KeyExchange.PublicKey) throws -> (rootKey: Bytes, chainKey: Bytes) {
        let dhResult = try dh(keyPair: keyPair, publicKey: remotePublicKey)
        return try deriveFromRootKDF(rootKey: rootKey, dhOut: dhResult, info: info)
    }
}
