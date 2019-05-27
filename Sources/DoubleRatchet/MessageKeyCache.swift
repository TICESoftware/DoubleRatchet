public struct MessageKeyCache {
    private struct MessageIndex: Hashable {
        let publicKey: PublicKey
        let messageNumber: Int
    }

    private var skippedMessageKeys: [MessageIndex: MessageKey]
    private var messageKeyCache: [MessageIndex]
    let maxCache: Int

    public var cacheState: MessageKeyCacheState {
        return messageKeyCache.map { MessageKeyCacheEntry(publicKey: $0.publicKey, messageNumber: $0.messageNumber, messageKey: skippedMessageKeys[$0]!) }
    }

    init(maxCache: Int, cacheState: MessageKeyCacheState = []) {
        self.maxCache = maxCache
        self.skippedMessageKeys = [:]
        self.messageKeyCache = []

        for cacheEntry in cacheState {
            add(messageKey: cacheEntry.messageKey, messageNumber: cacheEntry.messageNumber, publicKey: cacheEntry.publicKey)
        }
    }

    mutating func add(messageKey: MessageKey, messageNumber: Int, publicKey: PublicKey) {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        skippedMessageKeys[messageIndex] = messageKey
        messageKeyCache.append(messageIndex)

        while messageKeyCache.count > maxCache {
            let removedIndex = messageKeyCache.removeFirst()
            skippedMessageKeys[removedIndex] = nil
        }
    }

    mutating func getMessageKey(messageNumber: Int, publicKey: PublicKey) -> MessageKey? {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        guard let messageKey = skippedMessageKeys[messageIndex] else { return nil }

        skippedMessageKeys[messageIndex] = nil
        messageKeyCache.removeAll { $0 == messageIndex }

        return messageKey
    }
}

public typealias MessageKeyCacheState = [MessageKeyCacheEntry]
public struct MessageKeyCacheEntry: Codable {
    public let publicKey: PublicKey
    public let messageNumber: Int
    public let messageKey: MessageKey

    public init(publicKey: PublicKey, messageNumber: Int, messageKey: MessageKey) {
        self.publicKey = publicKey
        self.messageNumber = messageNumber
        self.messageKey = messageKey
    }
}
