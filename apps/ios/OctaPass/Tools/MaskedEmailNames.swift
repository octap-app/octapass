import OctaPassVault

enum MaskedEmailNames {
    /// A masked email provider's name, from its id (`addy` → addy.io).
    static func name(_ provider: String) -> String {
        maskedEmailProviders().first { $0.id == provider }?.name ?? provider
    }
}
