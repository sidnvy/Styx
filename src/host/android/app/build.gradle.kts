plugins { id("com.android.application") }

val workspaceVersion = rootProject.file("../../../Cargo.toml").readLines()
    .map { it.trim() }.dropWhile { it != "[workspace.package]" }.drop(1)
    .takeWhile { !it.startsWith("[") }.first { it.startsWith("version =") }
    .substringAfter('"').substringBefore('"')
val releaseKeystore = providers.environmentVariable("STYX_ANDROID_KEYSTORE")

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
        if (releaseKeystore.isPresent) {
            create("release") {
                storeFile = file(releaseKeystore.get())
                storePassword = providers.environmentVariable("STYX_ANDROID_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("STYX_ANDROID_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("STYX_ANDROID_KEY_PASSWORD").get()
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseKeystore.isPresent) signingConfig = signingConfigs.getByName("release")
        }
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
