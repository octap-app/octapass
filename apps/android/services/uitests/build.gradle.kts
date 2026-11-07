// The native smoke tests (src/androidTest) and the test app they fill (src/main), separate from
// Octa Pass so it fills them as it would any other app; it's also the other password manager in
// the credential transfer tests. scripts/android-ui-tests.sh runs them.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.octap.android.uitests"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.octap.android.test"
        minSdk = 28
        targetSdk = 36
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.credentials:credentials:1.6.0")
    // The other password manager in the credential transfer tests.
    implementation("androidx.credentials.providerevents:providerevents:1.0.0-beta01")
    implementation("androidx.credentials.providerevents:providerevents-play-services:1.0.0-beta01")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.4.0")
}
