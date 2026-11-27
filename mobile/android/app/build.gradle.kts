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
        versionCode = 17
        versionName = "0.4.7"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    // owner-core's generated Kotlin bindings and its arm64 library (build-core.sh)
    sourceSets["main"].kotlin.srcDir("build/generated/uniffi")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// A release build is the one that can be handed to someone, so it must not
// leave in the development posture (issue #35): the provisional package, or
// a core that knows the test chain. The CLI's half of the gate is its
// `distribution` feature (agent-signer/src/attestation.rs).
gradle.taskGraph.whenReady {
    if (allTasks.none { it.project == project && it.name.contains("Release") }) return@whenReady
    val core = file("src/main/jniLibs/arm64-v8a/libowner_core.so")
    val problems = listOfNotNull(
        "the application id ${android.defaultConfig.applicationId} is provisional: the package is the owner's decision (docs/APP_ATTEST_ORG.md §8)"
            .takeIf { android.defaultConfig.applicationId.orEmpty().endsWith(".spike") },
        "no owner-core library: run ./build-core.sh".takeIf { !core.exists() },
        "owner-core was built with test-chains: run ./build-core.sh without OWNER_CORE_FEATURES"
            .takeIf { core.exists() && String(core.readBytes(), Charsets.ISO_8859_1).contains("+test-chains") },
    )
    if (problems.isNotEmpty()) throw GradleException("not a build to hand to anyone:\n  - " + problems.joinToString("\n  - "))
}

dependencies {
    // Pinned to the last versions that compile against API 34 (newer ones need
    // compileSdk 37 and AGP 9.1).
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.biometric:biometric:1.1.0")
    // QR scanning (Apache-2.0): zxing-android-embedded + zxing core, no Google ML Kit
    // (docs/MOBILE_LICENSE_STUDY.md §3).
    implementation("com.journeyapps:zxing-android-embedded:4.3.0") { isTransitive = false }
    implementation("com.google.zxing:core:3.5.4")
    // uniffi's Kotlin bindings load owner-core through JNA (Apache-2.0 / LGPL dual)
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}
