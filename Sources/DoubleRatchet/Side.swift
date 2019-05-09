import Sodium

enum Side: String, Codable {
    case alice
    case bob

    var kxSide: KeyExchange.Side {
        return self == .alice ? .CLIENT : .SERVER
    }
}
