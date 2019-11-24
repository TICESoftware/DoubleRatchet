//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Sodium

public typealias ChainKey = Bytes

struct MessageChain {
    private let sodium = Sodium()
    private let messageKeyInput = Bytes([UInt8(1)])
    private let chainKeyInput = Bytes([UInt8(2)])

    var chainKey: ChainKey?

    init(chainKey: ChainKey? = nil) {
        self.chainKey = chainKey
    }

    // KDF_CK(ck)
    mutating func nextMessageKey() throws -> Bytes {
        guard let chainKey = chainKey else {
            throw DRError.chainKeyMissing
        }

        guard let messageKey = sodium.auth.tag(message: messageKeyInput, secretKey: chainKey),
            let newChainKey = sodium.auth.tag(message: chainKeyInput, secretKey: chainKey) else {
                throw DRError.messageChainRatchetStepFailed
        }
        self.chainKey = newChainKey
        return messageKey
    }
}
