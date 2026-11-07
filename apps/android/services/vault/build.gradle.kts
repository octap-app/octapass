// What the app and its autofill and credential services share: the Keystore-backed secrets, the
// device-unlock key and its prompt, the shared folder, and the core's Kotlin bindings
// (`apps/android/core`), which load the app's own Rust library (see `Core.kt`).
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.octap.android.vault"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDir("../../core/src/main/kotlin")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.19.1@aar")
    api("androidx.biometric:biometric:1.1.0")
    api("androidx.appcompat:appcompat:1.7.1")
    testImplementation("junit:junit:4.13.2")
    // The platform's org.json is only a stub in JVM unit tests.
    testImplementation("org.json:json:20250517")
}
