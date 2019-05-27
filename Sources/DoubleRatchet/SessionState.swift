//
//  Copyright © 2019 Anbion. All rights reserved.
//

public struct SessionState {
    public let info: String
    public let maxSkip: Int
    public let maxCache: Int

    public let rootKey: RootKey
    public let rootChainKeyPair: KeyPair
    public let rootChainRemotePublicKey: PublicKey?
    public let sendingChainKey: ChainKey?
    public let receivingChainKey: ChainKey?

    public let sendMessageNumber: Int
    public let receivedMessageNumber: Int
    public let previousSendingChainLength: Int
    public let messageKeyCacheState: MessageKeyCacheState

    public init(rootKey: RootKey, rootChainKeyPair: KeyPair, rootChainRemotePublicKey: PublicKey?, sendingChainKey: ChainKey?, receivingChainKey: ChainKey?, sendMessageNumber: Int, receivedMessageNumber: Int, previousSendingChainLength: Int, messageKeyCacheState: MessageKeyCacheState, info: String, maxSkip: Int, maxCache: Int) {
        self.rootKey = rootKey
        self.rootChainKeyPair = rootChainKeyPair
        self.rootChainRemotePublicKey = rootChainRemotePublicKey
        self.sendingChainKey = sendingChainKey
        self.receivingChainKey = receivingChainKey
        self.sendMessageNumber = sendMessageNumber
        self.receivedMessageNumber = receivedMessageNumber
        self.previousSendingChainLength = previousSendingChainLength
        self.messageKeyCacheState = messageKeyCacheState
        self.info = info
        self.maxSkip = maxSkip
        self.maxCache = maxCache
    }
}
