import Foundation
import Sodium

public struct Message {
    let header: Header
    let cipher: Bytes
}

struct Header: Codable {
    let publicKey: KeyExchange.PublicKey
    let numberOfMessagesInPreviousSendingChain: Int
    let messageNumber: Int

    func bytes() throws -> Bytes {
        let headerData = try JSONEncoder().encode(self)
        return Bytes(headerData)
    }
}
