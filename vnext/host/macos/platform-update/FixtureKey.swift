import Foundation
import CryptoKit
// Fixture-only key in a private directory, never stored in any Keychain.
let key = Curve25519.Signing.PrivateKey()
let file = CommandLine.arguments[1]
FileManager.default.createFile(atPath: file, contents: key.rawRepresentation.base64EncodedData(), attributes: [.posixPermissions: 0o600])
print(key.publicKey.rawRepresentation.base64EncodedString())
