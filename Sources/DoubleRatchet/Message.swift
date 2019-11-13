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

    func bytes() throws -> Bytes {
        var bytes = publicKey
        bytes.append(UInt8(numberOfMessagesInPreviousSendingChain))
        bytes.append(UInt8(messageNumber))
        return bytes
    }
}
