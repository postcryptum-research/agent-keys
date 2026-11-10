import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    // P0 spike. The application id is provisional: the bundle id / package is
    // the owner's decision and is fixed once P3 starts (docs/APP_ATTEST_ORG.md §8).
    namespace = "dev.tpmsign.owner.spike"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.tpmsign.owner.spike"
        minSdk = 30          // Android 11: setUserAuthenticationParameters (design D7)
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1-p0"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    // Pinned to the last versions that compile against API 34 (newer ones need
    // compileSdk 37 and AGP 9.1).
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.biometric:biometric:1.1.0")
}
