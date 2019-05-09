import Sodium
import HKDF

typealias KeyPair = KeyExchange.KeyPair
typealias PublicKey = KeyExchange.PublicKey
typealias MessageKey = Bytes

public class DoubleRatchet {
    private let sodium = Sodium()

    let maxSkip: Int

    private var rootChain: RootChain
    private var sendingChain: MessageChain
    private var receivingChain: MessageChain

    private var sentMessageNumber: Int
    private var receivedMessageNumber: Int
    private var previousSendingChainLength: Int
    private var skippedMessageKeys: [MessageIndex: MessageKey]

    var publicKey: PublicKey {
        return rootChain.keyPair.publicKey
    }

    struct MessageIndex: Hashable {
        let publicKey: PublicKey
        let messageNumber: Int
    }

    init(remotePublicKey: PublicKey?, sharedSecret: Bytes, maxSkip: Int, info: String) throws {
        guard sharedSecret.count == 32 else {
            throw DRError.invalidSharedSecret
        }

        self.maxSkip = maxSkip

        guard let keyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }

        self.rootChain = RootChain(keyPair: keyPair, remotePublicKey: remotePublicKey, rootKey: sharedSecret, info: info, side: remotePublicKey != nil ? .alice : .bob)
        self.sendingChain = MessageChain()
        self.receivingChain = MessageChain()

        self.sentMessageNumber = 0
        self.receivedMessageNumber = 0
        self.previousSendingChainLength = 0
        self.skippedMessageKeys = [:]

        if remotePublicKey != nil {
            sendingChain.chainKey = try self.rootChain.ratchetStep()
        }
    }

    func encrypt(message: Bytes) throws -> Message {
        let messageKey = try sendingChain.nextMessageKey()
        let header = Header(publicKey: rootChain.keyPair.publicKey, numberOfMessagesInPreviousSendingChain: previousSendingChainLength, messageNumber: sentMessageNumber)
        sentMessageNumber += 1

        let headerData = try header.bytes()
        guard let cipher: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: messageKey, additionalData: headerData) else {
            throw DRError.encryptionFailed
        }
        return Message(header: header, cipher: cipher)
    }

    func decrypt(message: Message) throws -> Bytes {
        if let plaintext = try decryptSkippedMessage(message) {
            return plaintext
        }

        let remotePublicKey = rootChain.remotePublicKey ?? message.header.publicKey
        if message.header.publicKey != rootChain.remotePublicKey {
            try skipReceivedMessages(until: message.header.numberOfMessagesInPreviousSendingChain, remotePublicKey: remotePublicKey)
            try doubleRatchetStep(publicKey: message.header.publicKey)
        }

        try skipReceivedMessages(until: message.header.messageNumber, remotePublicKey: remotePublicKey)

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

    private func decrypt(message: Message, key: MessageKey) throws -> Bytes {
        let headerData = try message.header.bytes()
        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: message.cipher, secretKey: key, additionalData: headerData) else {
            throw DRError.decryptionFailed
        }
        return plaintext
    }

    private func skipReceivedMessages(until nextMessageNumber: Int, remotePublicKey: PublicKey) throws {
        guard nextMessageNumber - receivedMessageNumber <= maxSkip else {
            throw DRError.exceedMaxSkip
        }

        while receivedMessageNumber < nextMessageNumber {
            let skippedMessageKey = try receivingChain.nextMessageKey()
            let skippedMessageIndex = MessageIndex(publicKey: remotePublicKey, messageNumber: receivedMessageNumber)
            skippedMessageKeys[skippedMessageIndex] = skippedMessageKey
            receivedMessageNumber += 1
        }
    }

    private func doubleRatchetStep(publicKey: KeyExchange.PublicKey) throws {
        previousSendingChainLength = receivedMessageNumber
        receivedMessageNumber = 0
        sentMessageNumber = 0

        rootChain.remotePublicKey = publicKey

        receivingChain.chainKey = try rootChain.ratchetStep()

        guard let newKeyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }
        rootChain.keyPair = newKeyPair

        sendingChain.chainKey = try rootChain.ratchetStep()
    }
}
