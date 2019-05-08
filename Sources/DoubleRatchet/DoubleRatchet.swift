import Sodium
import HKDF

public class DoubleRatchet {
    static let sodium = Sodium()

    let maxSkip: Int
    let info: String

    var rootChain: RootChain
    let sendingChain: MessageChain
    let receivingChain: MessageChain

    var sentMessageNumber: Int
    var receivedMessageNumber: Int
    var numberOfMessagesInPreviousSendingChain: Int
    var skippedMessageKeys: [SkippedMessageKeysIndex: Bytes]

    struct SkippedMessageKeysIndex: Hashable {
        let publicKey: KeyExchange.PublicKey
        let messageNumber: Int
    }

    init(remotePublicKey: KeyExchange.PublicKey?, sharedSecret: Bytes, maxSkip: Int, info: String) throws {
        self.maxSkip = maxSkip
        self.info = info

        let keyPair = try DoubleRatchet.generateDHKeyPair()
        self.rootChain = RootChain(dhRatchetKeyPair: keyPair, rootKey: sharedSecret)

        if let remotePublicKey = remotePublicKey {
            // TODO: If a remote public key is given update root chain
            // self.rootChain.ratchetStep()
            // self.sendingChain = ...

            // For now:
            self.sendingChain = MessageChain(chainKey: [])
        } else {
            self.sendingChain = MessageChain(chainKey: [])
        }

        self.receivingChain = MessageChain(chainKey: [])

        self.sentMessageNumber = 0
        self.receivedMessageNumber = 0
        self.numberOfMessagesInPreviousSendingChain = 0
        self.skippedMessageKeys = [:]
    }

    func encrypt(message: Bytes) throws -> Message {
        let messageKey = try sendingChain.nextMessageKey()
        let header = Header(publicKey: rootChain.currentPublicKey, numberOfMessagesInPreviousSendingChain: numberOfMessagesInPreviousSendingChain, messageNumber: sentMessageNumber)
        sentMessageNumber += 1

        let headerData = try header.bytes()
        guard let cipher: Bytes = DoubleRatchet.sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: messageKey, additionalData: headerData) else {
            throw DRError.encryptionFailed
        }
        return Message(header: header, cipher: cipher)
    }

    func decrypt(message: Message) throws -> Bytes {
        let headerData = try message.header.bytes()

        // Check for skipped messages
        let skippedMessageKeysIndex = SkippedMessageKeysIndex(publicKey: message.header.publicKey, messageNumber: message.header.messageNumber)
        if let messageKey = skippedMessageKeys[skippedMessageKeysIndex] {
            guard let plaintext = DoubleRatchet.sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: message.cipher, secretKey: messageKey, additionalData: headerData) else {
                throw DRError.decryptionFailed
            }
            skippedMessageKeys[skippedMessageKeysIndex] = nil
            return plaintext
        }

        // Check if ratchet step should be performed
        if message.header.publicKey != rootChain.currentPublicKey {
            // Skip messages if necessary (put into function?)
            guard message.header.numberOfMessagesInPreviousSendingChain - receivedMessageNumber <= maxSkip else {
                throw DRError.exceedMaxSkip
            }

            while receivedMessageNumber < message.header.numberOfMessagesInPreviousSendingChain {
                let skippedMessageKey = try receivingChain.nextMessageKey()
                let skippedMessageKeysIndex = SkippedMessageKeysIndex(publicKey: rootChain.currentPublicKey, messageNumber: receivedMessageNumber)
                skippedMessageKeys[skippedMessageKeysIndex] = skippedMessageKey
                receivedMessageNumber += 1
            }

            // Do ratchet step
            numberOfMessagesInPreviousSendingChain = receivedMessageNumber
            receivedMessageNumber = 0
            sentMessageNumber = 0

            let (intermediateRootKey, newReceivingChainKey) = try DoubleRatchet.deriveChainKeys(sharedSecret: rootChain.rootKey, info: info, keyPair: rootChain.dhRatchetKeyPair, remotePublicKey: message.header.publicKey)
            receivingChain.set(chainKey: newReceivingChainKey)
            let newKeyPair = try DoubleRatchet.generateDHKeyPair()
            let (newRootKey, newSendingChainKey) = try DoubleRatchet.deriveChainKeys(sharedSecret: intermediateRootKey, info: info, keyPair: newKeyPair, remotePublicKey: message.header.publicKey)
            rootChain.rootKey = newRootKey
            sendingChain.set(chainKey: newSendingChainKey)
        }

        // Skip messages if necessary (put into function?)
        guard message.header.messageNumber - receivedMessageNumber <= maxSkip else {
            throw DRError.exceedMaxSkip
        }

        while receivedMessageNumber < message.header.messageNumber {
            let skippedMessageKey = try receivingChain.nextMessageKey()
            let skippedMessageKeysIndex = SkippedMessageKeysIndex(publicKey: rootChain.currentPublicKey, messageNumber: receivedMessageNumber)
            skippedMessageKeys[skippedMessageKeysIndex] = skippedMessageKey
            receivedMessageNumber += 1
        }

        let messageKey = try receivingChain.nextMessageKey()
        guard let plaintext = DoubleRatchet.sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: message.cipher, secretKey: messageKey, additionalData: headerData) else {
            throw DRError.decryptionFailed
        }
        receivedMessageNumber += 1
        return plaintext
    }

    // GENERATE_DH()
    static func generateDHKeyPair() throws -> KeyExchange.KeyPair {
        guard let keyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }
        return keyPair
    }

    // DH(dh_pair, dh_pub)
    static func dh(keyPair: KeyExchange.KeyPair, publicKey: KeyExchange.PublicKey) throws -> Bytes {
        guard let dh = sodium.keyExchange.sessionKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, otherPublicKey: publicKey, side: .CLIENT) else {
            throw DRError.dhKeyExchangeFailed
        }
        return dh.rx
    }

    // KDF_RK(rk, dh_out)
    static func deriveFromRootKDF(rootKey: Bytes, dhOut: Bytes, info: String) throws -> (rootKey: Bytes, chainKey: Bytes) {
        let derivedKey = try deriveHKDFKey(ikm: dhOut, salt: rootKey, info: info, L: 64)
        return (rootKey: Bytes(derivedKey[..<32]), chainKey: Bytes(derivedKey[32...]))
    }

    static func deriveChainKeys(sharedSecret: Bytes, info: String, keyPair: KeyExchange.KeyPair, remotePublicKey: KeyExchange.PublicKey) throws -> (rootKey: Bytes, chainKey: Bytes) {
        let dhResult = try dh(keyPair: keyPair, publicKey: remotePublicKey)
        return try deriveFromRootKDF(rootKey: sharedSecret, dhOut: dhResult, info: info)
    }
}
