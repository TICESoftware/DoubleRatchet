import Foundation

public class MessageKeyCache {
    private struct MessageIndex: Hashable {
        let publicKey: PublicKey
        let messageNumber: Int
    }

    private let cacheQueue = DispatchQueue(label: "software.tice.DoubleRatchet.MessageKeyCache", attributes: .concurrent)
    private var skippedMessageKeys: [MessageIndex: MessageKey]
    private var messageKeyCache: [MessageIndex]
    let maxCache: Int

    public var cacheState: MessageKeyCacheState {
        cacheQueue.sync {
            return messageKeyCache.compactMap {
                guard let messageKey = skippedMessageKeys[$0] else { return nil }
                return MessageKeyCacheEntry(publicKey: $0.publicKey, messageNumber: $0.messageNumber, messageKey: messageKey)
            }
        }
    }

    init(maxCache: Int, cacheState: MessageKeyCacheState = []) {
        self.maxCache = maxCache
        self.skippedMessageKeys = [:]
        self.messageKeyCache = []

        for cacheEntry in cacheState {
            add(messageKey: cacheEntry.messageKey, messageNumber: cacheEntry.messageNumber, publicKey: cacheEntry.publicKey)
        }
    }

    func add(messageKey: MessageKey, messageNumber: Int, publicKey: PublicKey) {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)

        cacheQueue.async(flags: .barrier) {
            self.skippedMessageKeys[messageIndex] = messageKey
            self.messageKeyCache.append(messageIndex)

            while self.messageKeyCache.count > self.maxCache {
                let removedIndex = self.messageKeyCache.removeFirst()
                self.skippedMessageKeys[removedIndex] = nil
            }
        }
    }

    func getMessageKey(messageNumber: Int, publicKey: PublicKey) -> MessageKey? {
        let messageIndex = MessageIndex(publicKey: publicKey, messageNumber: messageNumber)
        guard let messageKey = cacheQueue.sync (execute: { skippedMessageKeys[messageIndex] }) else { return nil }

        cacheQueue.async(flags: .barrier) {
            self.skippedMessageKeys[messageIndex] = nil
            self.messageKeyCache.removeAll { $0 == messageIndex }
        }
        
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
