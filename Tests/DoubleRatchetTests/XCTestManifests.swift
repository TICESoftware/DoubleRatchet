//
//  Copyright © 2019 Anbion. All rights reserved.
//

import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(DoubleRatchetTests.allTests),
    ]
}
#endif
