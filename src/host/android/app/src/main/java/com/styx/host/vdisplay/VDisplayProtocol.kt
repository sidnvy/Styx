package com.styx.host.vdisplay

import android.os.IBinder
import android.view.KeyEvent

/** Wire constants and strict input validation rules for the Tier 2 UID-2000 virtual display helper. */
object VDisplayProtocol {
    const val INTERFACE_DESCRIPTOR = "com.styx.host.vdisplay.IVDisplayHelper"
    const val PROVIDER_AUTHORITY = "com.styx.host.vdisplay.binder"
    const val METHOD_REGISTER_BINDER = "register_binder"
    const val EXTRA_BINDER = "binder"
    const val EXTRA_APP_TOKEN = "app_token"
    const val EXTRA_VERSION = "version"
    const val PROTOCOL_VERSION = "1"
    const val TX_CALL = IBinder.FIRST_CALL_TRANSACTION
    const val MAX_MANAGED_DISPLAYS = 4

    val PACKAGE_NAME_REGEX = Regex("^[a-zA-Z0-9_]+(\\.[a-zA-Z0-9_]+)+$")
    val ACTIVITY_NAME_REGEX = Regex("^[a-zA-Z0-9_.$/]+$")
    val DISPLAY_NAME_REGEX = Regex("^[a-zA-Z0-9._-]{1,48}$")

    val ALLOWED_NAV_KEYCODES = setOf(
        KeyEvent.KEYCODE_HOME,
        KeyEvent.KEYCODE_BACK,
        KeyEvent.KEYCODE_APP_SWITCH,
    )
}
