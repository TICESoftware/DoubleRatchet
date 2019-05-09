import Sodium

struct MessageChain {
    private let sodium = Sodium()
    private let messageKeyInput = Bytes([UInt8(1)])
    private let chainKeyInput = Bytes([UInt8(2)])

    var chainKey: Bytes

    init(chainKey: Bytes) {
        self.chainKey = chainKey
    }

    // KDF_CK(ck)
    mutating func nextMessageKey() throws -> Bytes {
        guard let messageKey = sodium.auth.tag(message: messageKeyInput, secretKey: chainKey),
            let newChainKey = sodium.auth.tag(message: chainKeyInput, secretKey: chainKey) else {
                throw DRError.messageChainRatchetStepFailed
        }
        chainKey = newChainKey
        return messageKey
    }
}
