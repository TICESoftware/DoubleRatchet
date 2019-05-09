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

    func testRatchetSteps() {
        do {
            let bobPublicKeySnapshot = bob.publicKey

            let message = "aliceToBob".bytes
            let encryptedMessage = try alice.encrypt(message: message)
            let decryptedMessage = try bob.decrypt(message: encryptedMessage)
            XCTAssertEqual(message, decryptedMessage)
            XCTAssertNotEqual(bob.publicKey, bobPublicKeySnapshot)

            let alicePublicKeySnapshot = alice.publicKey

            let response = "bobToAlice".bytes
            let encryptedResponse = try bob.encrypt(message: response)
            let decryptedResponse = try alice.decrypt(message: encryptedResponse)
            XCTAssertEqual(response, decryptedResponse)
            XCTAssertNotEqual(alice.publicKey, alicePublicKeySnapshot)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    static var allTests = [
        ("testRatchetSteps", testRatchetSteps),
    ]
}
