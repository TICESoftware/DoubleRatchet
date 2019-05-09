import Sodium
import HKDF

typealias RootKey = Bytes

struct RootChain {
    let sodium = Sodium()

    var keyPair: KeyPair
    var remotePublicKey: PublicKey?
    var rootKey: RootKey
    let info: String
    let side: Side

    mutating func ratchetStep() throws -> ChainKey {
        guard let remotePublicKey = remotePublicKey else {
            throw DRError.remotePublicKeyMissing
        }

        let dhResult = try dh(keyPair: keyPair, publicKey: remotePublicKey)
        let (newRootKey, newChainKey) = try deriveFromRootKDF(rootKey: rootKey, dhOut: dhResult, info: info)
        rootKey = newRootKey
        return newChainKey
    }

    private func dh(keyPair: KeyExchange.KeyPair, publicKey: KeyExchange.PublicKey) throws -> Bytes {
        guard let dh = sodium.keyExchange.sessionKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, otherPublicKey: publicKey, side: side.kxSide) else {
            throw DRError.dhKeyExchangeFailed
        }
        return side == .alice ? dh.rx : dh.tx
    }

    private func deriveFromRootKDF(rootKey: Bytes, dhOut: Bytes, info: String) throws -> (rootKey: Bytes, chainKey: Bytes) {
        let derivedKey = try deriveHKDFKey(ikm: dhOut, salt: rootKey, info: info, L: 64)
        return (rootKey: Bytes(derivedKey[..<32]), chainKey: Bytes(derivedKey[32...]))
    }
}
