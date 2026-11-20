plugins { id("com.android.application") }

android {
    namespace = "com.styx.host"
    compileSdk = 36
    ndkVersion = "29.0.14206865"
    defaultConfig {
        applicationId = "com.styx.host"
        minSdk = 30
        targetSdk = 36
        testInstrumentationRunner = "com.styx.host.test.PlatformAcceptanceInstrumentation"
        versionCode = 1
        versionName = "0.6.0-android-dev"
        ndk { abiFilters += "arm64-v8a" }
    }
    buildTypes { release { isMinifyEnabled = false } }
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
