//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Sodium

enum Side {
    case sending
    case receiving

    var kxSide: KeyExchange.Side {
        return self == .sending ? .SERVER : .CLIENT
    }
}
