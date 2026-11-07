import Foundation
import OctaPassResources
import OctaPassVault

extension Error {
    /// The vault's error code, when the vault failed.
    var vaultCode: ErrorCode? {
        guard let error = self as? VaultError, case let .Failed(code, _) = error else { return nil }
        return code
    }

    func isVault(_ code: ErrorCode) -> Bool { vaultCode == code }

    /// The vault's reason, for the few messages that show it (`env.importFailed`): it never
    /// holds a secret.
    var reason: String {
        guard let error = self as? VaultError, case let .Failed(_, reason) = error else { return message }
        return reason
    }

    /// What to tell the user: the catalog's `errors.<code>`, as the web vault says it.
    var message: String {
        guard let code = vaultCode else { return L10n.errors.unexpected }
        return L10n.text(forKey: "errors.\(errorCodeName(code: code))") ?? L10n.errors.unexpected
    }
}
