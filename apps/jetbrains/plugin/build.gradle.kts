// The plugin: the IDE side of the Connect client in `client/`. Built against IntelliJ IDEA 2024.1,
// the newest platform that runs on JDK 17.
import org.jetbrains.intellij.platform.gradle.extensions.intellijPlatform
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    kotlin("jvm")
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        // At run time the IDE supplies the standard library: 1.9.22 in 2024.1. Language 2.0 is the
        // oldest this compiler still accepts.
        apiVersion = KotlinVersion.KOTLIN_1_9
        languageVersion = KotlinVersion.KOTLIN_2_0
    }
}

dependencies {
    implementation(project(":client"))
    intellijPlatform {
        intellijIdeaCommunity("2024.1.7")
        bundledPlugin("org.jetbrains.plugins.terminal")
    }
}

intellijPlatform {
    // Starting an IDE to index settings, and instrumenting forms, are neither needed here.
    buildSearchableOptions = false
    instrumentCode = false
    pluginConfiguration {
        version = "0.1.0"
        ideaVersion {
            sinceBuild = "241"
            untilBuild = provider { null }
        }
    }
}

tasks.buildPlugin {
    archiveBaseName = "octapass-jetbrains"
}
