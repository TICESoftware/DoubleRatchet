import Sodium
import HKDF

public struct DoubleRatchet {
    let sodium: Sodium
    let maxSkip: Int
    let info: String

    var dhRatchetKeyPair: KeyExchange.KeyPair
    var dhRemotePublicKey: KeyExchange.PublicKey
    var rootKey: Bytes
    var sendingChainKey: Bytes
    var receivingChainKey: Bytes?
    var sentMessageNumber: Int
    var receivedMessageNumber: Int
    var numberOfMessagesInPreviousSendingChain: Int
    var skippedMessages: [Int]

    init(keyPair: KeyExchange.KeyPair, remotePublicKey: KeyExchange.PublicKey, sharedSecret: Bytes, maxSkip: Int, info: String) throws {
        self.sodium = Sodium()
        self.maxSkip = maxSkip
        self.info = info

        self.dhRatchetKeyPair = try generateDHKeyPair()
        self.dhRemotePublicKey = remotePublicKey

        (self.rootKey, self.sendingChainKey) = try deriveChainKeys(sharedSecret: sharedSecret, info: info, keyPair: self.dhRatchetKeyPair, remotePublicKey: self.dhRemotePublicKey)

        self.sentMessageNumber = 0
        self.receivedMessageNumber = 0
        self.numberOfMessagesInPreviousSendingChain = 0
        self.skippedMessages = []
    }
}

// GENERATE_DH()
func generateDHKeyPair() throws -> KeyExchange.KeyPair {
    guard let keyPair = Sodium().keyExchange.keyPair() else {
        throw DRError.dhKeyGenerationFailed
    }
    return keyPair
}

// DH(dh_pair, dh_pub)
func dh(keyPair: KeyExchange.KeyPair, publicKey: KeyExchange.PublicKey) throws -> Bytes {
    guard let dh = Sodium().keyExchange.sessionKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, otherPublicKey: publicKey, side: .CLIENT) else {
        throw DRError.dhKeyExchangeFailed
    }
    return dh.rx
}

// KDF_RK(rk, dh_out)
func deriveFromRootKDF(rootKey: Bytes, dhOut: Bytes, info: String) throws -> (rootKey: Bytes, chainKey: Bytes) {
    let derivedKey = try deriveHKDFKey(ikm: dhOut, salt: rootKey, info: info, L: 64)
    return (rootKey: Bytes(derivedKey[..<32]), chainKey: Bytes(derivedKey[32...]))
}

func deriveChainKeys(sharedSecret: Bytes, info: String, keyPair: KeyExchange.KeyPair, remotePublicKey: KeyExchange.PublicKey) throws -> (rootKey: Bytes, chainKey: Bytes) {
    let dhResult = try dh(keyPair: keyPair, publicKey: remotePublicKey)
    return try deriveFromRootKDF(rootKey: sharedSecret, dhOut: dhResult, info: info)
}
