package com.styx.host.test

import android.app.Activity
import android.app.Instrumentation
import android.app.UiAutomation
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Base64
import com.styx.host.AndroidPlatform
import org.json.JSONArray
import org.json.JSONObject

/** Real Android APIs against the test APK's own Activity; launch with am instrument --no-restart. */
class PlatformAcceptanceInstrumentation : Instrumentation() {
    private lateinit var platform: AndroidPlatform
    private lateinit var automation: UiAutomation
    private val passed = JSONArray()
    private val measurements = JSONObject()
    private var currentCase = "initialization"
    private var lastErrorCode: String? = null
    private val callerA = "android-fixture-a"
    private val callerB = "android-fixture-b"

    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }
    override fun onStart() {
        var success = false
        val result = JSONObject().put("sdk", Build.VERSION.SDK_INT)
        try {
            automation = getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES)
            platform = AndroidPlatform(targetContext)
            checkCase("accessibility_connected_without_suppression") {
                await(8000) { JSONObject(platform.execute("status", "{}")).optBoolean("accessibility") }
                check(!JSONObject(platform.execute("status", "{}")).getBoolean("device_locked"))
            }
            context.startActivity(Intent(context, FixtureActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            checkCase("fixture_foreground") {
                await(5000) { fixtureIsForeground() }
                automation.waitForIdle(500, 5000)
            }

            checkCase("tree_and_independent_callers") {
                val first = observe(callerA)
                observe(callerB)
                requireOk(act(callerA, first, nodeAction("click", node(first, "android:id/button1"))))
                assertCounter(1)
            }
            checkCase("old_observation_rejected") {
                val old = observe(callerA)
                observe(callerA)
                val rejected = act(callerA, old, nodeAction("click", node(old, "android:id/button1")))
                check(errorCode(rejected) == "stale_observation")
                assertCounter(1)
            }
            checkCase("unicode_set_text") {
                val observed = observe(callerA)
                val text = "Styx 中文 👋 café"
                requireOk(act(callerA, observed, nodeAction("set_text", node(observed, "android:id/edit")).put("text", text)))
                await(2000) { node(observe(callerA), "android:id/edit").optString("text") == text }
            }
            checkCase("coordinate_gesture") {
                val observed = observe(callerA)
                val bounds = node(observed, "android:id/button1").getJSONArray("bounds")
                requireOk(act(callerA, observed, JSONObject().put("type", "tap")
                    .put("x", (bounds.getInt(0) + bounds.getInt(2)) / 2.0)
                    .put("y", (bounds.getInt(1) + bounds.getInt(3)) / 2.0)))
                assertCounter(2)
            }
            checkCase("batch_two_real_clicks") {
                val observed = observe(callerA)
                val click = nodeAction("click", node(observed, "android:id/button1"))
                val batch = call("android_run_steps", callerA, JSONObject()
                    .put("observation_id", observed.getString("observation_id"))
                    .put("steps", JSONArray().put(click).put(JSONObject(click.toString()))))
                requireOk(batch); check(batch.getInt("completed_steps") == 2)
                assertCounter(4)
            }
            checkCase("batch_keeps_partial_results") {
                val observed = observe(callerA)
                val batch = call("android_run_steps", callerA, JSONObject()
                    .put("observation_id", observed.getString("observation_id"))
                    .put("steps", JSONArray()
                        .put(nodeAction("click", node(observed, "android:id/button1")))
                        .put(nodeAction("set_text", node(observed, "android:id/edit")))))
                check(!batch.getBoolean("ok") && batch.getInt("completed_steps") == 1)
                check(batch.getInt("failed_step") == 1 && batch.getJSONArray("results").length() == 2)
                check(errorCode(batch) == "invalid_arguments")
                assertCounter(5)
            }
            checkCase("tree_latency") {
                val samples = JSONArray()
                repeat(5) {
                    val start = SystemClock.elapsedRealtimeNanos()
                    observe(callerA)
                    samples.put((SystemClock.elapsedRealtimeNanos() - start) / 1_000_000.0)
                }
                measurements.put("tree_ms", samples)
            }
            checkCase("fixture_screenshot") {
                val start = SystemClock.elapsedRealtimeNanos()
                val observed = screenshot()
                measurements.put("screenshot_ms", (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000.0)
                val bitmap = bitmap(observed)
                check(colourFraction(bitmap, false) > 0.25)
                measurements.put("screenshot_width", bitmap.width).put("screenshot_height", bitmap.height)
                bitmap.recycle()
            }
            checkCase("secure_fixture_protected") {
                val observed = observe(callerA)
                requireOk(act(callerA, observed, nodeAction("click", node(observed, "android:id/button2"))))
                await(2000) { node(observe(callerA), "android:id/text2").optString("text") == "Secure: on" }
                // Android throttles screenshots; this separates the two deliberate captures.
                Thread.sleep(400)
                val secured = screenshot()
                if (secured.has("screenshot_error")) {
                    check(secured.getJSONObject("screenshot_error").getString("code") == "secure_window")
                    measurements.put("secure_capture", "refused")
                } else {
                    val bitmap = bitmap(secured)
                    check(colourFraction(bitmap, true) > 0.95)
                    bitmap.recycle()
                    measurements.put("secure_capture", "black_redacted_bitmap")
                }
            }
            checkCase("caller_release_and_host_clear") {
                val a = observe(callerA)
                call("release_caller", callerA, JSONObject())
                check(errorCode(act(callerA, a, nodeAction("click", node(a, "android:id/button1")))) == "stale_observation")
                val b = observe(callerB)
                call("clear", callerB, JSONObject())
                check(errorCode(act(callerB, b, nodeAction("click", node(b, "android:id/button1")))) == "stale_observation")
                assertCounter(5)
            }
            success = true
        } catch (error: Throwable) {
            result.put("failed_case", currentCase).put("error_type", error.javaClass.simpleName)
                .put("platform_error_code", lastErrorCode ?: JSONObject.NULL)
                .put("failed_at", error.stackTrace.firstOrNull { it.className.startsWith("com.styx.host.test.") }?.toString() ?: JSONObject.NULL)
        } finally {
            if (::platform.isInitialized) {
                platform.execute("release_caller", JSONObject().put("__caller_id", callerA).toString())
                platform.execute("release_caller", JSONObject().put("__caller_id", callerB).toString())
            }
            if (::automation.isInitialized && fixtureIsForeground()) {
                context.startActivity(Intent(context, FixtureActivity::class.java).putExtra("finish_fixture", true)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            }
            result.put("ok", success).put("passed_cases", passed).put("measurements", measurements)
            finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply { putString("result_json", result.toString()) })
        }
    }

    private fun checkCase(name: String, body: () -> Unit) { currentCase = name; body(); passed.put(name) }
    private fun await(timeoutMs: Long, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        do { if (condition()) return; Thread.sleep(50) } while (SystemClock.elapsedRealtime() < deadline)
        error("Fixture condition did not become ready")
    }
    private fun fixtureIsForeground(): Boolean {
        val root = automation.rootInActiveWindow ?: return false
        return try { root.packageName?.toString() == context.packageName } finally { root.recycle() }
    }
    private fun call(method: String, caller: String, params: JSONObject): JSONObject =
        JSONObject(platform.execute(method, params.put("__caller_id", caller).toString())).also { lastErrorCode = errorCode(it) }
    private fun observe(caller: String): JSONObject {
        check(fixtureIsForeground())
        val result = call("android_observe", caller, JSONObject())
        requireOk(result); check(result.getString("package_name") == context.packageName)
        return result
    }
    private fun screenshot(): JSONObject {
        check(fixtureIsForeground())
        val result = call("android_observe", callerA, JSONObject().put("include_tree", false).put("screenshot", true))
        requireOk(result); check(result.getString("package_name") == context.packageName)
        return result
    }
    private fun node(observed: JSONObject, viewId: String): JSONObject {
        val nodes = observed.getJSONArray("nodes")
        for (index in 0 until nodes.length()) {
            val node = nodes.getJSONObject(index)
            if (node.optString("view_id") == viewId) return node
        }
        error("Fixture node not found")
    }
    private fun nodeAction(type: String, node: JSONObject) = JSONObject().put("type", type).put("node_id", node.getString("node_id"))
    private fun act(caller: String, observed: JSONObject, action: JSONObject) = call("android_act", caller,
        JSONObject().put("observation_id", observed.getString("observation_id")).put("action", action))
    private fun requireOk(result: JSONObject) { check(result.optBoolean("ok", false)) }
    private fun errorCode(result: JSONObject) = result.optJSONObject("error")?.optString("code")
    private fun assertCounter(count: Int) { await(2000) { node(observe(callerA), "android:id/text1").optString("text") == "Clicks: $count" } }
    private fun bitmap(observed: JSONObject): Bitmap {
        val screenshot = observed.getJSONObject("screenshot")
        val bytes = Base64.decode(screenshot.getString("data"), Base64.NO_WRAP)
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: error("Invalid fixture bitmap")
    }
    private fun colourFraction(bitmap: Bitmap, black: Boolean): Double {
        var matching = 0
        var total = 0
        for (y in bitmap.height / 5 until bitmap.height * 4 / 5 step 4) {
            for (x in bitmap.width / 5 until bitmap.width * 4 / 5 step 4) {
                val pixel = bitmap.getPixel(x, y)
                val red = Color.red(pixel); val green = Color.green(pixel); val blue = Color.blue(pixel)
                val matches = if (black) red < 12 && green < 12 && blue < 12
                    else kotlin.math.abs(red - 55) < 20 && kotlin.math.abs(green - 114) < 20 && kotlin.math.abs(blue - 199) < 20
                if (matches) matching++
                total++
            }
        }
        return matching.toDouble() / total
    }
}
