import java.util.Properties

plugins { id("com.android.application") }

val workspaceVersion = rootProject.file("../../../Cargo.toml").readLines()
    .map { it.trim() }.dropWhile { it != "[workspace.package]" }.drop(1)
    .takeWhile { !it.startsWith("[") }.first { it.startsWith("version =") }
    .substringAfter('"').substringBefore('"')

// Fixed release signing comes from environment variables or an external
// signing.properties file outside the repository (never committed to Git).
val signingProps = Properties().apply {
    val propsPath = providers.environmentVariable("STYX_ANDROID_SIGNING_PROPERTIES").orNull
    if (!propsPath.isNullOrBlank()) {
        val propsFile = file(propsPath)
        require(propsFile.isFile) { "STYX_ANDROID_SIGNING_PROPERTIES file does not exist: $propsPath" }
        propsFile.inputStream().use { load(it) }
    }
}
fun signingSetting(envName: String, propName: String): String? =
    providers.environmentVariable(envName).orNull?.takeIf { it.isNotBlank() }
        ?: signingProps.getProperty(propName)?.takeIf { it.isNotBlank() }

val releaseKeystorePath = signingSetting("STYX_ANDROID_KEYSTORE", "storeFile")
val debugKeystorePath = providers.environmentVariable("STYX_ANDROID_DEBUG_KEYSTORE").orNull?.takeIf { it.isNotBlank() }

android {
    namespace = "com.styx.host"
    compileSdk = 36
    ndkVersion = "29.0.14206865"
    defaultConfig {
        applicationId = "com.styx.host"
        minSdk = 30
        targetSdk = 36
        testInstrumentationRunner = "com.styx.host.test.PlatformAcceptanceInstrumentation"
        versionCode = providers.environmentVariable("STYX_ANDROID_VERSION_CODE").orElse("1").get().toInt()
        versionName = providers.environmentVariable("STYX_ANDROID_VERSION_NAME").orElse("$workspaceVersion-android-dev").get()
        ndk { abiFilters += "arm64-v8a" }
    }
    signingConfigs {
        if (debugKeystorePath != null) {
            getByName("debug") {
                storeFile = file(debugKeystorePath)
                storePassword = providers.environmentVariable("STYX_ANDROID_DEBUG_KEYSTORE_PASSWORD").orElse("android").get()
                keyAlias = providers.environmentVariable("STYX_ANDROID_DEBUG_KEY_ALIAS").orElse("androiddebugkey").get()
                keyPassword = providers.environmentVariable("STYX_ANDROID_DEBUG_KEY_PASSWORD").orElse("android").get()
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
        if (releaseKeystorePath != null) {
            create("release") {
                storeFile = file(releaseKeystorePath)
                storePassword = requireNotNull(signingSetting("STYX_ANDROID_KEYSTORE_PASSWORD", "storePassword")) {
                    "Set STYX_ANDROID_KEYSTORE_PASSWORD (or storePassword in signing.properties)"
                }
                keyAlias = requireNotNull(signingSetting("STYX_ANDROID_KEY_ALIAS", "keyAlias")) {
                    "Set STYX_ANDROID_KEY_ALIAS (or keyAlias in signing.properties)"
                }
                keyPassword = requireNotNull(signingSetting("STYX_ANDROID_KEY_PASSWORD", "keyPassword")) {
                    "Set STYX_ANDROID_KEY_PASSWORD (or keyPassword in signing.properties)"
                }
                // minSdk=30: v2/v3 only avoids legacy JAR v1 tampering and supports key rotation.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (releaseKeystorePath != null) signingConfig = signingConfigs.getByName("release")
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
    lint {
        // Keep offline reproducible release builds independent of uncached lint-gradle downloads.
        checkReleaseBuilds = false
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rust-jni").get().asFile)
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

val nativeLibrary = providers.environmentVariable("STYX_ANDROID_NATIVE_LIB")
    .orElse(rootProject.layout.projectDirectory.file("../../../target/aarch64-linux-android/debug/libstyx_android.so").asFile.absolutePath)
val syncRustLibrary = tasks.register<Sync>("syncRustLibrary") {
    from(nativeLibrary)
    into(layout.buildDirectory.dir("rust-jni/arm64-v8a"))
    doFirst {
        require(file(nativeLibrary.get()).isFile) {
            "Build styx-android for aarch64-linux-android first, or set STYX_ANDROID_NATIVE_LIB."
        }
    }
}
tasks.configureEach {
    if (name in setOf("mergeDebugJniLibFolders", "mergeReleaseJniLibFolders", "mergeDebugNativeLibs", "mergeReleaseNativeLibs")) dependsOn(syncRustLibrary)
}
