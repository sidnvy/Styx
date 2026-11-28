package com.styx.host.vdisplay

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Process

/** Accepts only live Binder registration from UID 2000 (shell) or UID 0 (root). */
class VDisplayBinderProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val callingUid = Binder.getCallingUid()
        if (callingUid != Process.SHELL_UID && callingUid != Process.ROOT_UID) {
            throw SecurityException("Unauthorized caller UID $callingUid for vdisplay binder registration")
        }
        if (method != VDisplayProtocol.METHOD_REGISTER_BINDER) {
            throw IllegalArgumentException("Unsupported provider method: $method")
        }
        val binder = extras?.getBinder(VDisplayProtocol.EXTRA_BINDER)
            ?: throw IllegalArgumentException("Missing helper binder extra")
        if (!binder.isBinderAlive) {
            throw IllegalArgumentException("Submitted helper binder is not alive")
        }
        val appToken = VDisplayClient.register(binder)
        return Bundle().apply {
            putBinder(VDisplayProtocol.EXTRA_APP_TOKEN, appToken)
            putString(VDisplayProtocol.EXTRA_VERSION, VDisplayProtocol.PROTOCOL_VERSION)
        }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        throw UnsupportedOperationException("VDisplayBinderProvider does not store rows")
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
        throw UnsupportedOperationException("VDisplayBinderProvider does not store rows")
    }

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int {
        throw UnsupportedOperationException("VDisplayBinderProvider does not store rows")
    }
}
