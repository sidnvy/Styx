package com.styx.host.vdisplay

import android.os.Binder
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Parcel
import android.os.RemoteException
import android.os.SharedMemory
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/** Holds the live Binder registered by the UID-2000 vdisplay-helper process and marshals typed calls. */
object VDisplayClient {
    private val lock = Any()
    private var helperBinder: IBinder? = null
    private var deathRecipient: IBinder.DeathRecipient? = null
    private val appToken = Binder()

    val isConnected: Boolean
        get() = synchronized(lock) {
            val current = helperBinder
            if (current != null && current.isBinderAlive) {
                true
            } else {
                if (current != null) clearLocked(current)
                false
            }
        }

    fun register(binder: IBinder): IBinder {
        synchronized(lock) {
            val previous = helperBinder
            val previousDeath = deathRecipient
            if (previous != null && previousDeath != null) {
                runCatching { previous.unlinkToDeath(previousDeath, 0) }
            }
            val recipient = IBinder.DeathRecipient {
                synchronized(lock) {
                    if (helperBinder === binder) {
                        helperBinder = null
                        deathRecipient = null
                    }
                }
            }
            helperBinder = binder
            deathRecipient = recipient
            binder.linkToDeath(recipient, 0)
            return appToken
        }
    }

    private fun clearLocked(expected: IBinder) {
        if (helperBinder === expected) {
            val previousDeath = deathRecipient
            if (previousDeath != null) {
                runCatching { expected.unlinkToDeath(previousDeath, 0) }
            }
            helperBinder = null
            deathRecipient = null
        }
    }

    fun listManagedDisplayIds(): Set<Int> {
        if (!isConnected) return emptySet()
        val (json, _) = transact("list_displays", JSONObject())
        if (!json.optBoolean("ok", false)) return emptySet()
        val arr = json.optJSONArray("managed_display_ids") ?: return emptySet()
        val ids = linkedSetOf<Int>()
        for (i in 0 until arr.length()) {
            ids.add(arr.getInt(i))
        }
        return ids
    }

    fun isManagedDisplay(displayId: Int): Boolean =
        displayId > 0 && displayId in listManagedDisplayIds()

    fun createDisplay(name: String, width: Int, height: Int, densityDpi: Int): JSONObject {
        val params = JSONObject()
            .put("name", name)
            .put("width", width)
            .put("height", height)
            .put("density_dpi", densityDpi)
        return transact("create_display", params).first
    }

    fun destroyDisplay(displayId: Int): JSONObject {
        val params = JSONObject().put("display_id", displayId)
        return transact("destroy_display", params).first
    }

    fun launchApp(
        packageName: String,
        activity: String?,
        displayId: Int,
        clearTask: Boolean,
    ): JSONObject {
        val params = JSONObject()
            .put("package_name", packageName)
            .put("display_id", displayId)
            .put("clear_task", clearTask)
        if (!activity.isNullOrBlank()) {
            params.put("activity", activity)
        }
        return transact("launch_app", params).first
    }

    fun captureDisplay(displayId: Int, maxDimension: Int): JSONObject {
        val params = JSONObject()
            .put("display_id", displayId)
            .put("max_dimension", maxDimension)
        val (json, bytes) = transact("capture_display", params)
        if (!json.optBoolean("ok", false)) return json
        if (bytes == null || bytes.isEmpty()) {
            return failure("screenshot_failed", "Virtual display capture returned empty image data.")
        }
        val screenshot = JSONObject()
            .put("mime_type", json.optString("mime_type", "image/jpeg"))
            .put("data", Base64.encodeToString(bytes, Base64.NO_WRAP))
            .put("width", json.optInt("width"))
            .put("height", json.optInt("height"))
        return JSONObject()
            .put("ok", true)
            .put("screenshot", screenshot)
    }

    fun injectKey(displayId: Int, keyCode: Int): JSONObject {
        val params = JSONObject()
            .put("display_id", displayId)
            .put("key_code", keyCode)
        return transact("inject_key", params).first
    }

    fun injectTouch(
        displayId: Int,
        x: Float,
        y: Float,
        endX: Float,
        endY: Float,
        durationMs: Long,
    ): JSONObject {
        val params = JSONObject()
            .put("display_id", displayId)
            .put("x", x.toDouble())
            .put("y", y.toDouble())
            .put("end_x", endX.toDouble())
            .put("end_y", endY.toDouble())
            .put("duration_ms", durationMs)
        return transact("inject_touch", params).first
    }

    private fun transact(method: String, params: JSONObject): Pair<JSONObject, ByteArray?> {
        val target = synchronized(lock) {
            val current = helperBinder
            if (current == null || !current.isBinderAlive) {
                if (current != null) clearLocked(current)
                null
            } else {
                current
            }
        } ?: return failure(
            "vdisplay_helper_unavailable",
            "Styx vdisplay helper is not connected; start vdisplay-helper.sh via ADB.",
        ) to null

        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        var shm: SharedMemory? = null
        try {
            data.writeInterfaceToken(VDisplayProtocol.INTERFACE_DESCRIPTOR)
            data.writeString(JSONObject().put("method", method).put("params", params).toString())
            val ok = target.transact(VDisplayProtocol.TX_CALL, data, reply, 0)
            if (!ok) {
                synchronized(lock) { clearLocked(target) }
                return failure(
                    "vdisplay_helper_unavailable",
                    "Styx vdisplay helper binder call was rejected.",
                ) to null
            }
            reply.readException()
            val responseJson = JSONObject(reply.readString() ?: "{}")
            val hasShm = reply.readInt() != 0
            if (hasShm) {
                shm = SharedMemory.CREATOR.createFromParcel(reply)
                val length = responseJson.optInt("byte_length", 0)
                if (length > 0 && shm != null) {
                    val buf = shm.mapReadOnly()
                    try {
                        val bytes = ByteArray(length)
                        buf.get(bytes)
                        return responseJson to bytes
                    } finally {
                        SharedMemory.unmap(buf)
                    }
                }
            }
            return responseJson to null
        } catch (_: DeadObjectException) {
            synchronized(lock) { clearLocked(target) }
            return failure(
                "vdisplay_helper_unavailable",
                "Styx vdisplay helper disconnected; restart vdisplay-helper.sh via ADB.",
                uncertain = method in setOf("inject_touch", "inject_key", "launch_app"),
            ) to null
        } catch (error: RemoteException) {
            synchronized(lock) { clearLocked(target) }
            return failure(
                "vdisplay_helper_error",
                "Styx vdisplay helper remote failure: ${error.message ?: "unknown"}.",
                uncertain = method in setOf("inject_touch", "inject_key", "launch_app"),
            ) to null
        } catch (error: Exception) {
            return failure(
                "vdisplay_helper_error",
                "Styx vdisplay helper call failed: ${error.message ?: error.javaClass.simpleName}.",
                uncertain = method in setOf("inject_touch", "inject_key", "launch_app"),
            ) to null
        } finally {
            runCatching { shm?.close() }
            reply.recycle()
            data.recycle()
        }
    }

    private fun failure(code: String, message: String, uncertain: Boolean = false): JSONObject =
        JSONObject()
            .put("ok", false)
            .put(
                "error",
                JSONObject()
                    .put("code", code)
                    .put("message", message)
                    .put("uncertain", uncertain),
            )
}
