import Foundation

public enum DRError: LocalizedError {
    case dhKeyGenerationFailed
    case dhKeyExchangeFailed

    public var errorDescription: String? {
        switch self {
        case .dhKeyGenerationFailed: return "DH keypair could not be created."
        case .dhKeyExchangeFailed: return "DH failed."
        }
    }
}
