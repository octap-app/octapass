// Octa Pass in other apps: the Autofill service (Android 9+, inline suggestions on 11+), the
// Credential Manager provider for passwords and passkeys (Android 14+), and credential transfer
// to and from other password managers, on the store the app shares with them (`:octapass-vault`).
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.octap.android.autofill"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation(project(":octapass-vault"))
    implementation("androidx.autofill:autofill:1.3.0")
    implementation("androidx.credentials:credentials:1.6.0")
    // Credential transfer (FIDO Credential Exchange) between password managers, through Google
    // Play services (`providerevents-play-services`).
    api("androidx.credentials.providerevents:providerevents:1.0.0-beta01")
    implementation("androidx.credentials.providerevents:providerevents-play-services:1.0.0-beta01")
    implementation("androidx.core:core-ktx:1.17.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
