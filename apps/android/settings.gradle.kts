// The native Android app (plan 17): the Compose app, the generated strings and tokens, and the
// Autofill and Credential Manager services. `vault/` (the OctaPassVault bindings) and `core/` (the
// octapass-ffi bindings) are their own JVM builds for the binding tests. The app compiles `vault/`'s
// sources and packages its jniLibs; the services compile `core/`'s sources.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // rustls-platform-verifier's Kotlin half (its README, "Gradle setup").
        maven {
            url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/")
            content { includeGroup("org.rustls") }
        }
    }
}

rootProject.name = "octapass-android"

include(":app", ":wear", ":resources", ":octapass-vault", ":octapass-autofill", ":octapass-uitests")
project(":octapass-vault").projectDir = file("services/vault")
project(":octapass-autofill").projectDir = file("services/autofill")
project(":octapass-uitests").projectDir = file("services/uitests")
