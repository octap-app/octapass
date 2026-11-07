import OctaPassVault

/// The vault's `DeviceLock`. `OctaPassKeychain` has one too, and the module's own `OctaPassVault`
/// class hides the module name, so files that import both use this name.
typealias VaultDeviceLock = DeviceLock
