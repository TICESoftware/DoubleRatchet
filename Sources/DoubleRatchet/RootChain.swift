import Sodium
import HKDF

struct RootChain {
    var dhRatchetKeyPair: KeyExchange.KeyPair
    var rootKey: Bytes

    var currentPublicKey: KeyExchange.PublicKey {
        return dhRatchetKeyPair.publicKey
    }
}
