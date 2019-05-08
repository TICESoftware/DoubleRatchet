import Sodium

class MessageChain {
    private let sodium = Sodium()
    private let messageKeyInput = Bytes([UInt8(1)])
    private let chainKeyInput = Bytes([UInt8(2)])

    private var chainKey: Bytes

    init(chainKey: Bytes) {
        self.chainKey = chainKey
    }

    // KDF_CK(ck)
    func nextMessageKey() throws -> Bytes {
        guard let messageKey = sodium.auth.tag(message: messageKeyInput, secretKey: chainKey),
            let newChainKey = sodium.auth.tag(message: chainKeyInput, secretKey: chainKey) else {
                throw DRError.messageChainRatchetStepFailed
        }
        chainKey = newChainKey
        return messageKey
    }

    func set(chainKey: Bytes) {
        self.chainKey = chainKey
    }
}
