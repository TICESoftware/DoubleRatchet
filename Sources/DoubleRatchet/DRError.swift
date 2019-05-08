import Foundation

public enum DRError: LocalizedError {
    case dhKeyGenerationFailed
    case dhKeyExchangeFailed
    case messageChainRatchetStepFailed
    case encryptionFailed
    case decryptionFailed
    case exceedMaxSkip

    public var errorDescription: String? {
        switch self {
        case .dhKeyGenerationFailed: return "DH keypair could not be created."
        case .dhKeyExchangeFailed: return "DH failed."
        case .messageChainRatchetStepFailed: return "Could not do ratchet step in message chain."
        case .encryptionFailed: return "Encryption failed."
        case .decryptionFailed: return "Decryption failed."
        case .exceedMaxSkip: return "Cannot skip more messages than defined by MAX_SKIP."
        }
    }
}
