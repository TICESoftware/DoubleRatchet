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
    public let skippedMessageKeys: [DoubleRatchet.MessageIndex: MessageKey]
    public let messageKeyCache: [DoubleRatchet.MessageIndex]
}
