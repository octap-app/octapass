// The Octa Pass plugin for JetBrains IDEs. `client/` is the Connect client and needs no IntelliJ
// Platform, so `./gradlew :client:test` runs without downloading it. `plugin/` is the rest.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "octapass-jetbrains"

include(":client", ":plugin")
