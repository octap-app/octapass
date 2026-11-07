// Written by hand, unlike L10n.swift: messages by their catalog key, for keys the vault API
// hands back (`errors.<code>` from `errorCodeName`, a draft's `validation.*` keys, item type
// names) rather than ones the app names itself.

import Foundation

extension L10n {
    /// The message for `key` in the current language, or nil when the catalog has none.
    public static func text(forKey key: String) -> String? {
        let text = string(key)
        return text == key ? nil : text
    }

    /// The message for `key` with its arguments, in the order of the format's positions.
    public static func text(forKey key: String, _ arguments: any CVarArg...) -> String? {
        guard text(forKey: key) != nil else { return nil }
        return format(key, arguments: arguments)
    }

    /// The locale messages are formatted in: the shown language, Western digits.
    public static var formatLocale: Locale { locale }
}
