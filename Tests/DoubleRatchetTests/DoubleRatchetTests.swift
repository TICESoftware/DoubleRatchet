import XCTest
import Sodium
@testable import DoubleRatchet

final class DoubleRatchetTests: XCTestCase {

    let sodium = Sodium()
    let sharedSecret = Sodium().utils.hex2bin("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF", ignore: " ")!

    var alice: DoubleRatchet!
    var bob: DoubleRatchet!
    let info = "DoubleRatchetTest"

    override func setUp() {
        super.setUp()

        bob = try! DoubleRatchet(remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, info: info)
        alice = try! DoubleRatchet(remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, info: info)
    }

    func testConversationWithoutRatchetStep() {
        do {
            for _ in 0...1 {
                let message = "aliceToBob".bytes
                let encryptedMessage = try alice.encrypt(message: message)
                let decryptedMessage = try bob.decrypt(message: encryptedMessage)
                XCTAssertEqual(message, decryptedMessage)

                for _ in 0...1 {
                    let message = "bobToAlice".bytes
                    let encryptedMessage = try bob.encrypt(message: message)
                    let decryptedMessage = try alice.decrypt(message: encryptedMessage)
                    XCTAssertEqual(message, decryptedMessage)
                }
            }
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testConversationWithRatchetStep() {
        XCTFail("Not implemented yet.")
    }

    static var allTests = [
        ("testConversationWithoutRatchetStep", testConversationWithoutRatchetStep),
        ("testConversationWithRatchetStep", testConversationWithRatchetStep),
    ]
}
