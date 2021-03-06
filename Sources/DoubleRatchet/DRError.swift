//
//  Copyright © 2020 TICE Software UG (haftungsbeschränkt). All rights reserved.
//

import Foundation

public enum DRError: Error, CustomStringConvertible {
    case invalidSharedSecret
    case dhKeyGenerationFailed
    case dhKeyExchangeFailed
    case chainKeyMissing
    case messageChainRatchetStepFailed
    case encryptionFailed
    case decryptionFailed
    case exceedMaxSkip
    case remotePublicKeyMissing
    case discardOldMessage

    public var description: String {
        switch self {
        case .invalidSharedSecret: return "Shared secret must be 32 bytes."
        case .dhKeyGenerationFailed: return "DH keypair could not be created."
        case .dhKeyExchangeFailed: return "DH failed."
        case .chainKeyMissing: return "Message chain does not have a chain key."
        case .messageChainRatchetStepFailed: return "Could not do ratchet step in message chain."
        case .encryptionFailed: return "Encryption failed."
        case .decryptionFailed: return "Decryption failed."
        case .exceedMaxSkip: return "Cannot skip more messages than defined by MAX_SKIP."
        case .remotePublicKeyMissing: return "The other party's public key is not available."
        case .discardOldMessage: return "Message is being discarded because it is older than the oldest cached message."
        }
    }
}
