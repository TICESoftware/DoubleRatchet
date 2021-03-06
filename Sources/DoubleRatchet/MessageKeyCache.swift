//
//  Copyright © 2020 TICE Software UG (haftungsbeschränkt). All rights reserved.
//

import Foundation

public protocol MessageKeyCache {
    func add(messageKey: MessageKey, messageNumber: Int, publicKey: PublicKey) throws
    func getMessageKey(messageNumber: Int, publicKey: PublicKey) throws -> MessageKey?
    func remove(publicKey: PublicKey, messageNumber: Int) throws
}
