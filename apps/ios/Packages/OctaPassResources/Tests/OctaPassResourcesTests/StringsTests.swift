import Foundation
import Testing
@testable import OctaPassResources

/// One message with sample arguments and what the web vault shows for it (Resources/expected.json,
/// written by tools/native-resources).
struct Expectation: Decodable {
    enum Argument: Decodable {
        case int(Int)
        case text(String)

        init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let n = try? container.decode(Int.self) { self = .int(n) } else { self = .text(try container.decode(String.self)) }
        }

        var value: any CVarArg {
            switch self {
            case .int(let n): n
            case .text(let s): s
            }
        }
    }

    let key: String
    let locale: String
    let args: [Argument]
    let expected: String
}

// The language is global, so these run one at a time.
@Suite(.serialized)
struct StringsTests {
    static let expectations: [Expectation] = {
        let url = Bundle.module.url(forResource: "expected", withExtension: "json")!
        return try! JSONDecoder().decode([Expectation].self, from: Data(contentsOf: url))
    }()

    static func use(_ language: String) {
        L10n.setLanguage(language)
        #expect(L10n.language == language)
    }

    @Test(arguments: ["en", "ar"])
    func everyCaseMatchesTheWebVault(language: String) throws {
        Self.use(language)
        defer { L10n.setLanguage(nil) }
        let cases = Self.expectations.filter { $0.locale == language }
        #expect(cases.count > 300)
        // The web vault isolates inserted text in Arabic always; Foundation does too, unless the
        // format has no right-to-left letters ("%1$@، %2$@"). Compare without the marks, which only
        // order text, and check isolation itself in arabicPluralForms().
        let unisolated = { (s: String) in s.replacingOccurrences(of: "\u{2068}", with: "").replacingOccurrences(of: "\u{2069}", with: "") }
        var failures: [String] = []
        for c in cases {
            let shown = c.args.isEmpty ? L10n.string(c.key) : L10n.format(c.key, arguments: c.args.map(\.value))
            if unisolated(shown) != unisolated(c.expected) { failures.append("\(c.key) \(c.args): \"\(shown)\", expected \"\(c.expected)\"") }
        }
        #expect(failures.isEmpty, "\(failures.count) differ:\n\(failures.prefix(20).joined(separator: "\n"))")
    }

    @Test func englishAccessors() throws {
        Self.use("en")
        defer { L10n.setLanguage(nil) }
        #expect(L10n.common.back == "Back")
        #expect(L10n.common.revealWhat(what: "PIN") == "Show PIN")
        #expect(L10n.list.searchPlaceholder(count: 1) == "Search 1 item")
        #expect(L10n.list.searchPlaceholder(count: 12) == "Search 12 items")
        #expect(L10n.detail.codesLeft(left: 2, count: 5) == "2 of 5 backup codes left")
        #expect(L10n.signUp.stepOf(step: 1, total: 3) == "Step 1 of 3")
        #expect(L10n.editor.fixErrors(count: 1) == "Fix the highlighted field to save.")
        #expect(L10n.deleteAccount.sharedVaults(vaults: "Family", count: 1).hasPrefix("You’re the only owner of Family. It will"))
        #expect(L10n.generator.symbols == "Symbols (!#$%)")
        #expect(L10n.strength.score._0.isEmpty == false)
        #expect(L10n.import.help._2fas.contains("2FAS"))
        #expect(L10n.phone.qrHidesIn(count: 5) == "Hides in 5 s")
        #expect(L10n.phone.choices.wifi == "Join Wi-Fi")
    }

    @Test func arabicPluralForms() throws {
        Self.use("ar")
        defer { L10n.setLanguage(nil) }
        #expect(L10n.list.searchPlaceholder(count: 0) == "ابحث في العناصر")
        #expect(L10n.list.searchPlaceholder(count: 1) == "ابحث في عنصر واحد")
        #expect(L10n.list.searchPlaceholder(count: 2) == "ابحث في عنصرين")
        #expect(L10n.list.searchPlaceholder(count: 3) == "ابحث في 3 عناصر")
        #expect(L10n.list.searchPlaceholder(count: 11) == "ابحث في 11 عنصرًا")
        #expect(L10n.list.searchPlaceholder(count: 100) == "ابحث في 100 عنصر")
        // Two arguments; the zero form leaves out both the count and the date.
        #expect(L10n.viewer.viewsLeft(count: 0, date: "1 May") == "لا يمكن فتح هذا الرابط مرة أخرى.")
        // Foundation isolates inserted text in a right-to-left language, as the web vault does.
        #expect(L10n.viewer.viewsLeft(count: 4, date: "1 May") == "يمكن فتح هذا الرابط 4 مرات أخرى، حتى \u{2068}1 May\u{2069}.")
        // English counts nothing here; Arabic does.
        #expect(L10n.phone.qrHidesIn(count: 2) == "يختفي خلال ثانيتين")
        // Western digits, grouped as the web vault groups them.
        #expect(L10n.list.searchPlaceholder(count: 1234) == "ابحث في 1,234 عنصرًا")
    }

    @Test func unknownLanguageFallsBackToTheSystems() {
        L10n.setLanguage("xx")
        defer { L10n.setLanguage(nil) }
        #expect(["en", "ar"].contains(L10n.language))
    }
}
