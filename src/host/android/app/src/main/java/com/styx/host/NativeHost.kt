package com.styx.host

/** Rust owns identity, enrollment, authenticated transport, authorization and operation lifetime. */
object NativeHost {
    init { System.loadLibrary("styx_android") }
    @JvmStatic external fun pair(gatewayUrl: String, invitationCode: String, deviceLabel: String, platform: AndroidPlatform): String
    @JvmStatic external fun start(configJson: String, platform: AndroidPlatform): String
    @JvmStatic external fun stop(): String
    @JvmStatic external fun status(): String
}
