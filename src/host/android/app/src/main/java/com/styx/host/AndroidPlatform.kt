package com.styx.host

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import org.json.JSONException
import org.json.JSONObject

/** Called from Rust worker threads; Android does not own any Gateway session or trust state. */
class AndroidPlatform(context: Context) {
    private val context = context.applicationContext
    private val credentials = CredentialStore(context)
    fun loadCredentials(): String? = credentials.load()
    fun storeCredentials(json: String) { credentials.store(json) }
    fun forgetCredentials() { credentials.forget() }

    fun execute(method: String, paramsJson: String): String {
        if (method == "status") return readiness(context).toString()
        if (method == "clear") { StyxAccessibilityService.instance?.clearObservation(); return JSONObject().put("ok", true).toString() }
        if (method == "release_caller") {
            StyxAccessibilityService.instance?.releaseCaller(JSONObject(paramsJson).getString("__caller_id"))
            return JSONObject().put("ok", true).toString()
        }
        return synchronized(operationLock) {
            try {
                val service = StyxAccessibilityService.instance
                    ?: return@synchronized failure("permission_not_ready", "Enable Styx Android control in Accessibility settings.").toString()
                service.execute(method, JSONObject(paramsJson)).toString()
            } catch (error: JSONException) {
                failure("invalid_arguments", "Invalid Android request.").toString()
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                failure("operation_interrupted", "Android operation was interrupted; observe before issuing another action.", true).toString()
            } catch (error: Exception) {
                failure("android_operation_failed", "Android could not complete this operation; observe the current state.", true).toString()
            }
        }
    }

    companion object {
        private val operationLock = Any()
        fun readiness(context: Context): JSONObject = JSONObject()
            .put("accessibility", StyxAccessibilityService.instance != null)
            .put("device_locked", context.getSystemService(KeyguardManager::class.java).isKeyguardLocked)
            .put(
                "ignoring_battery_optimizations",
                context.getSystemService(PowerManager::class.java)
                    .isIgnoringBatteryOptimizations(context.packageName)
            )
        fun failure(code: String, message: String, uncertain: Boolean = false): JSONObject = JSONObject()
            .put("ok", false)
            .put("error", JSONObject().put("code", code).put("message", message).put("uncertain", uncertain))
    }
}
