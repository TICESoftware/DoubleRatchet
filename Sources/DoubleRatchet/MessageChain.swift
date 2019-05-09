import Sodium

typealias ChainKey = Bytes

struct MessageChain {
    private let sodium = Sodium()
    private let messageKeyInput = Bytes([UInt8(1)])
    private let chainKeyInput = Bytes([UInt8(2)])

    var chainKey: Bytes?

    // KDF_CK(ck)
    mutating func nextMessageKey() throws -> Bytes {
        guard let chainKey = chainKey,
            let messageKey = sodium.auth.tag(message: messageKeyInput, secretKey: chainKey),
            let newChainKey = sodium.auth.tag(message: chainKeyInput, secretKey: chainKey) else {
                throw DRError.messageChainRatchetStepFailed
        }
        self.chainKey = newChainKey
        return messageKey
    }
}
