//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Foundation
import Sodium

public struct Message: Codable {
    public let header: Header
    public let cipher: Bytes
}

public struct Header: Codable {
    public let publicKey: KeyExchange.PublicKey
    public let numberOfMessagesInPreviousSendingChain: Int
    public let messageNumber: Int

    public func bytes() throws -> Bytes {
        var bytes = publicKey
        bytes.append(contentsOf: byteArray(from: numberOfMessagesInPreviousSendingChain))
        bytes.append(contentsOf: byteArray(from: messageNumber))
        return bytes
    }

    private func byteArray(from value: Int) -> Bytes {
        return withUnsafeBytes(of: value.bigEndian) { Bytes($0) }
    }
}
