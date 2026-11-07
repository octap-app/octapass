// The native Octa Pass app for Android (plan 17): Jetpack Compose screens on OctaPassVault
// (`../vault`: the generated Kotlin bindings and `liboctapass_mobile.so`, built by
// crates/octapass-mobile/scripts/build-android.sh), with the Autofill and Credential Manager
// services from `services/`.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.octap.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.octap.android"
        minSdk = 28
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // The "Octa Pass" server choice; development builds point it elsewhere with
        // -PoctapassServer=http://localhost:8090 (the emulator reaches the Mac through adb reverse).
        buildConfigField("String", "DEFAULT_SERVER_URL", "\"${providers.gradleProperty("octapassServer").getOrElse("https://vault.octap.app")}\"")
        buildConfigField("String", "WEB_VAULT_URL", "\"https://vault.octap.app\"")
        manifestPlaceholders["usesCleartextTraffic"] = "false"
    }

    buildTypes {
        getByName("debug") {
            // Installs next to a release build (app.octap.android).
            applicationIdSuffix = ".native"
            manifestPlaceholders["usesCleartextTraffic"] = "true"
        }
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("../vault/src/main/kotlin", "../vault/src/android/kotlin")
            jniLibs.srcDir("../vault/jniLibs")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        jniLibs.keepDebugSymbols.add("**/*.so")
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

// rustls-platform-verifier's Kotlin half in the version Cargo.lock has: the vault's HTTPS clients
// check certificates through it.
abstract class RustlsVersion : ValueSource<String, RustlsVersion.Params> {
    interface Params : ValueSourceParameters {
        val lockFile: RegularFileProperty
    }

    override fun obtain(): String {
        val lines = parameters.lockFile.get().asFile.readLines()
        val name = lines.indexOfFirst { it.trim() == "name = \"rustls-platform-verifier-android\"" }
        return lines.drop(name + 1).first { it.trimStart().startsWith("version = ") }.substringAfter('"').substringBefore('"')
    }
}

val rustlsVersion = providers.of(RustlsVersion::class.java) {
    parameters.lockFile.set(rootProject.layout.projectDirectory.file("../../Cargo.lock"))
}

dependencies {
    implementation(project(":resources"))
    implementation(project(":octapass-vault"))
    implementation(project(":octapass-autofill"))
    implementation("org.rustls:rustls-platform-verifier:${rustlsVersion.get()}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    val compose = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(compose)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material3:material3-window-size-class")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    implementation("androidx.navigation3:navigation3-runtime:1.2.0")
    implementation("androidx.navigation3:navigation3-ui:1.2.0")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")
    // The data layer to a paired Wear OS watch (`platform/WatchCodes.kt`). Without Play services
    // the setting does nothing.
    implementation("com.google.android.gms:play-services-wearable:20.0.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
    androidTestImplementation(compose)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.4.0")
}
