package com.styx.host.test

import android.accessibilityservice.AccessibilityService
import android.app.Activity
import android.app.Instrumentation
import android.app.KeyguardManager
import android.app.UiAutomation
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.styx.host.MainActivity
import com.styx.host.NativeHost
import com.styx.host.StyxAccessibilityService
import java.io.File
import java.util.concurrent.atomic.AtomicReference
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
    private var mode: String? = null
    private var hostAction: String? = null
    private val callerA = "android-fixture-a"
    private val callerB = "android-fixture-b"

    override fun onCreate(arguments: Bundle?) {
        mode = arguments?.getString("mode")
        hostAction = arguments?.getString("action")
        super.onCreate(arguments); start()
    }
    override fun onStart() {
        if (mode == "pair_ui") { pairUsingUi(); return }
        if (mode == "forget_ui") { forgetUsingUi(); return }
        if (mode == "host_ui") { hostUsingUi(); return }
        if (mode == "keyguard") { keyguardUsingApi(); return }
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

            if (mode == "transition") {
                verifyActivityTransition()
                success = true
                return
            }
            checkCase("tree_and_independent_callers") {
                val first = observe(callerA)
                observe(callerB)
                requireOk(act(callerA, first, nodeAction("click", node(first, "android:id/button1"))))
                assertCounter(1)
            }
            checkCase("display_list_and_explicit_default") {
                val inventory = call("android_list_displays", callerA, JSONObject())
                requireOk(inventory)
                val displays = inventory.getJSONArray("displays")
                check((0 until displays.length()).any { displays.getJSONObject(it).getInt("display_id") == 0 })
                val explicit = call("android_observe", callerA, JSONObject().put("display_id", 0))
                requireOk(explicit)
                check(explicit.getInt("display_id") == 0)
                check(explicit.getJSONObject("display").getInt("width") > 0)
                val wrongDisplay = call("android_act", callerA, JSONObject()
                    .put("observation_id", explicit.getString("observation_id"))
                    .put("display_id", 42)
                    .put("action", JSONObject().put("type", "home")))
                check(errorCode(wrongDisplay) == "stale_observation")
                val missing = call("android_observe", callerA, JSONObject().put("display_id", 2147483647))
                check(errorCode(missing) == "display_not_found")
                val old = call("android_observe", callerA, JSONObject().put("display_id", 0))
                requireOk(old)
                check(errorCode(act(callerA, explicit, JSONObject().put("type", "home"))) == "stale_observation")
            }
            checkCase("old_observation_rejected") {
                val old = observe(callerA)
                observe(callerA)
                val rejected = act(callerA, old, nodeAction("click", node(old, "android:id/button1")))
                check(errorCode(rejected) == "stale_observation")
                assertCounter(1)
            }
            checkCase("unicode_set_text_and_relayout_click") {
                val observed = observe(callerA)
                val button = node(observed, "android:id/button1")
                val text = "Styx 中文 👋 café"
                requireOk(act(callerA, observed, nodeAction("set_text", node(observed, "android:id/edit")).put("text", text)))
                automation.waitForIdle(500, 5000)
                // Caller B verifies the real relayout without replacing caller A's observation.
                val changed = observe(callerB)
                check(node(changed, "android:id/edit").optString("text") == text)
                check(node(changed, "android:id/button1").getJSONArray("bounds").toString() != button.getJSONArray("bounds").toString())
                requireOk(act(callerA, observed, nodeAction("click", button)))
                assertCounter(2)
            }
            checkCase("coordinate_gesture") {
                val observed = observe(callerA)
                val bounds = node(observed, "android:id/button1").getJSONArray("bounds")
                requireOk(act(callerA, observed, JSONObject().put("type", "tap")
                    .put("x", (bounds.getInt(0) + bounds.getInt(2)) / 2.0)
                    .put("y", (bounds.getInt(1) + bounds.getInt(3)) / 2.0)))
                assertCounter(3)
            }
            checkCase("batch_two_real_clicks") {
                val observed = observe(callerA)
                val click = nodeAction("click", node(observed, "android:id/button1"))
                val batch = call("android_run_steps", callerA, JSONObject()
                    .put("observation_id", observed.getString("observation_id"))
                    .put("steps", JSONArray().put(click).put(JSONObject(click.toString())))
                    .put("observe_after", true))
                requireOk(batch); check(batch.getInt("completed_steps") == 2)
                val after = batch.getJSONObject("observation")
                requireOk(after)
                check(node(after, "android:id/text1").optString("text") == "Clicks: 5")
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
                assertCounter(6)
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
            checkCase("replacement_node_at_same_path_rejected") {
                val observed = observe(callerA)
                val oldButton = node(observed, "android:id/button1")
                context.startActivity(Intent(context, FixtureActivity::class.java).putExtra("replace_increment", true)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP))
                automation.waitForIdle(500, 5000)
                val replacement = node(observe(callerB), "android:id/button1")
                for (key in listOf("node_id", "view_id", "class_name", "text", "description", "bounds"))
                    check(oldButton.get(key).toString() == replacement.get(key).toString())
                check(errorCode(act(callerA, observed, nodeAction("click", oldButton))) == "stale_node")
                assertCounter(6)
            }
            checkCase("caller_release_and_host_clear") {
                val a = observe(callerA)
                call("release_caller", callerA, JSONObject())
                check(errorCode(act(callerA, a, nodeAction("click", node(a, "android:id/button1")))) == "stale_observation")
                val b = observe(callerB)
                call("clear", callerB, JSONObject())
                check(errorCode(act(callerB, b, nodeAction("click", node(b, "android:id/button1")))) == "stale_observation")
                assertCounter(6)
            }
            verifyActivityTransition()
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

    private fun verifyActivityTransition() {
        checkCase("batch_activity_transition_observe_after") {
            val before = observe(callerA)
            val transition = nodeAction("click", node(before, "android:id/button3"))
            try {
                val batch = call("android_run_steps", callerA, JSONObject()
                    .put("observation_id", before.getString("observation_id"))
                    .put("steps", JSONArray().put(transition))
                    .put("observe_after", true))
                requireOk(batch)
                check(batch.getInt("completed_steps") == 1)
                val after = batch.getJSONObject("observation")
                requireOk(after)
                check(node(after, "android:id/text1").optString("text") == "STYX NEXT TEST SCREEN") {
                    "The batch observed the old window before Activity transition completed"
                }
            } finally {
                context.startActivity(Intent(context, FixtureActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                await(5000) { fixtureIsForeground() }
            }
        }
    }

    /** One local setup action through the real Activity. Input never appears in test arguments/results. */
    private fun pairUsingUi() {
        val result = JSONObject().put("mode", "pair_ui")
        val observedError = AtomicReference<JSONObject?>()
        val confirmedPair = AtomicReference<JSONObject?>()
        var pairButton: Button? = null
        var statusView: TextView? = null
        var clicked = false
        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) { }
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { }
            override fun afterTextChanged(s: Editable?) {
                val value = try { JSONObject(s.toString()) } catch (_: Exception) {
                    if (s.toString().startsWith("Pairing failed.")) observedError.set(
                        JSONObject().put("code", "pairing_failed").put("uncertain", true))
                    return
                }
                if (value.optBoolean("ok") && value.optString("state") == "paired")
                    confirmedPair.set(publicStatus(value))
                val error = value.optJSONObject("error") ?: return
                observedError.set(JSONObject().put("code", error.optString("code", "pairing_failed"))
                    .put("uncertain", error.optBoolean("uncertain", false)))
            }
        }
        try {
            currentCase = "pair_ui_input"
            val file = File(targetContext.noBackupFilesDir, "styx-pairing-input.json")
            val input = try { JSONObject(file.readText()) } finally { check(file.delete()) }
            val gatewayUrl = input.getString("gateway_url")
            val shortCode = input.getString("short_code")
            val deviceLabel = input.optString("device_label", Build.MODEL)
            val activity = openMainActivity()
            currentCase = "pair_ui_fields"
            runOnMainSync {
                val all = descendants(activity.findViewById(android.R.id.content))
                fun field(hint: String, type: Int) = all.filterIsInstance<EditText>()
                    .single { it.hint?.toString() == hint && it.inputType == type }
                val gateway = field("Gateway URL", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
                val code = field("Invitation short code", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
                val label = field("Device name", InputType.TYPE_CLASS_TEXT)
                val pair = all.filterIsInstance<Button>().single { it.text.toString() == "Pair phone" }
                pairButton = pair
                currentCase = "pair_ui_ready"
                check(pair.isEnabled && pair.isShown && activity.hasWindowFocus())
                statusView = all.filterIsInstance<TextView>().single { it !is EditText && it.isTextSelectable }
                statusView!!.addTextChangedListener(watcher)
                gateway.setText(gatewayUrl); code.setText(shortCode); label.setText(deviceLabel)
                currentCase = "pair_ui_click"
                clicked = true
                check(pair.performClick())
            }
            currentCase = "pair_ui_result"
            val deadline = SystemClock.elapsedRealtime() + 45000
            var state: JSONObject
            do {
                state = publicHostStatus()
                var completed = false
                runOnMainSync { completed = pairButton!!.isEnabled }
                if (completed && (observedError.get() != null || confirmedPair.get() != null)) break
                Thread.sleep(50)
            } while (SystemClock.elapsedRealtime() < deadline)
            result.put("status", state)
            confirmedPair.get()?.let { result.put("pair_result", it) }
            val failure = observedError.get() ?: if (confirmedPair.get() == null)
                JSONObject().put("code", "pair_ui_timeout").put("uncertain", clicked) else null
            if (failure != null) result.put("error", failure)
            result.put("ok", failure == null && confirmedPair.get() != null)
        } catch (error: Throwable) {
            result.put("ok", false).put("error", JSONObject().put("code", "pair_ui_failed")
                .put("uncertain", clicked)).put("error_type", error.javaClass.simpleName)
                .put("stage", currentCase)
                .put("failed_at", error.stackTrace.firstOrNull { it.className.startsWith("com.styx.host.test.") }?.toString() ?: JSONObject.NULL)
        } finally {
            runOnMainSync { statusView?.removeTextChangedListener(watcher) }
            result.put("pair_button_clicked", clicked)
            finish(if (result.optBoolean("ok")) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply { putString("result_json", result.toString()) })
        }
    }

    /** Explicit local reset via the App button and standard confirmation, never direct storage mutation. */
    private fun forgetUsingUi() {
        val result = JSONObject().put("mode", "forget_ui")
        var confirmed = false
        try {
            val accessibility = AndroidPlatform.readiness(targetContext).getBoolean("accessibility")
            val activity = openMainActivity()
            automation = getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES)
            runOnMainSync {
                val button = descendants(activity.findViewById(android.R.id.content))
                    .filterIsInstance<Button>().single { it.text.toString() == "Forget pairing" }
                check(button.isEnabled && button.isShown && activity.hasWindowFocus())
                check(button.performClick())
            }
            await(5000) {
                val root = automation.rootInActiveWindow ?: return@await false
                try {
                    if (root.packageName?.toString() != targetContext.packageName) return@await false
                    val nodes = root.findAccessibilityNodeInfosByText("Forget")
                    try {
                        if (nodes.none { it.text?.toString() == "Forget pairing?" }) return@await false
                        val button = nodes.singleOrNull {
                            it.className?.toString() == "android.widget.Button" &&
                                it.text?.toString()?.equals("Forget", ignoreCase = true) == true && it.isEnabled
                        } ?: return@await false
                        confirmed = true
                        check(button.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK))
                        true
                    } finally { nodes.forEach { it.recycle() } }
                } finally { root.recycle() }
            }
            await(10000) { publicHostStatus().optString("code") == "pairing_forgotten" }
            val state = publicHostStatus()
            val absent = !File(targetContext.noBackupFilesDir, "styx-credentials").exists()
            val unchanged = AndroidPlatform.readiness(targetContext).getBoolean("accessibility") == accessibility
            result.put("status", state).put("credentials_absent", absent).put("accessibility_preserved", unchanged)
            check(absent && unchanged && !state.has("environment_id") && state.optString("state") == "stopped")
            result.put("ok", true)
        } catch (error: Throwable) {
            result.put("ok", false).put("error", JSONObject().put("code", "forget_ui_failed")
                .put("uncertain", confirmed)).put("error_type", error.javaClass.simpleName)
        } finally {
            result.put("confirmation_clicked", confirmed)
            finish(if (result.optBoolean("ok")) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply { putString("result_json", result.toString()) })
        }
    }

    /** Reads public lock state or requests one normal Accessibility lock, without changing security settings. */
    private fun keyguardUsingApi() {
        val action = hostAction ?: "status"
        val result = JSONObject().put("mode", "keyguard").put("action", action)
        var lockRequested = false
        var lockAccepted: Boolean? = null
        try {
            currentCase = "keyguard_arguments"
            require(action in listOf("status", "lock"))
            result.put("before", keyguardState())
            if (action == "lock") {
                currentCase = "keyguard_lock_request"
                val service = checkNotNull(StyxAccessibilityService.instance)
                lockRequested = true
                lockAccepted = service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_LOCK_SCREEN)
                check(lockAccepted == true)
                currentCase = "keyguard_lock_state"
                await(5000) { targetContext.getSystemService(KeyguardManager::class.java).isKeyguardLocked }
            }
            result.put("ok", true)
        } catch (error: Throwable) {
            result.put("ok", false).put("error", JSONObject().put("code", "keyguard_acceptance_failed")
                .put("uncertain", lockRequested && lockAccepted != false))
                .put("error_type", error.javaClass.simpleName).put("stage", currentCase)
        } finally {
            result.put("lock_requested", lockRequested).put("lock_accepted", lockAccepted ?: JSONObject.NULL)
                .put("after", keyguardState())
            finish(if (result.optBoolean("ok")) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply { putString("result_json", result.toString()) })
        }
    }

    private fun keyguardState(): JSONObject {
        val keyguard = targetContext.getSystemService(KeyguardManager::class.java)
        return JSONObject().put("is_keyguard_locked", keyguard.isKeyguardLocked)
            .put("is_device_locked", keyguard.isDeviceLocked).put("is_device_secure", keyguard.isDeviceSecure)
            .put("is_keyguard_secure", keyguard.isKeyguardSecure)
            .put("is_interactive", targetContext.getSystemService(PowerManager::class.java).isInteractive)
    }

    /** Finite lifecycle acceptance through the real buttons; status reads only the public JNI surface. */
    private fun hostUsingUi() {
        val result = JSONObject().put("mode", "host_ui")
        val action = hostAction ?: "status"
        var clicked = false
        try {
            currentCase = "host_ui_arguments"
            require(action in listOf("start", "stop", "status"))
            result.put("action", action).put("before", publicHostStatus())
            if (action != "status") {
                val activity = openMainActivity()
                currentCase = if (action == "start") "host_ui_start" else "host_ui_stop"
                runOnMainSync {
                    val title = if (action == "start") "Start Host" else "Stop Host"
                    val button = descendants(activity.findViewById(android.R.id.content))
                        .filterIsInstance<Button>().single { it.text.toString() == title }
                    check(button.isEnabled && button.isShown && activity.hasWindowFocus())
                    clicked = true
                    check(button.performClick())
                }
                currentCase = "host_ui_result"
                val expected = if (action == "start") "connected" else "stopped"
                await(if (action == "start") 45000 else 15000) {
                    publicHostStatus().optString("state") == expected
                }
                check(publicHostStatus().optString("state") == expected)
            }
            result.put("ok", true)
        } catch (error: Throwable) {
            result.put("ok", false).put("error", JSONObject().put("code", "host_ui_failed")
                .put("uncertain", clicked)).put("error_type", error.javaClass.simpleName)
                .put("stage", currentCase)
                .put("failed_at", error.stackTrace.firstOrNull { it.className.startsWith("com.styx.host.test.") }?.toString() ?: JSONObject.NULL)
        } finally {
            result.put("status", publicHostStatus()).put("permissions", AndroidPlatform.readiness(targetContext))
                .put("button_clicked", clicked)
            finish(if (result.optBoolean("ok")) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply { putString("result_json", result.toString()) })
        }
    }

    private fun openMainActivity(): Activity {
        currentCase = "main_activity_launch"
        val activity = startActivitySync(Intent(targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
        currentCase = "main_activity_focus"
        await(5000) {
            var ready = false
            runOnMainSync { ready = activity.hasWindowFocus() }
            ready
        }
        return activity
    }

    private fun descendants(view: View): List<View> = buildList {
        add(view)
        if (view is ViewGroup) for (index in 0 until view.childCount) addAll(descendants(view.getChildAt(index)))
    }

    private fun publicHostStatus() = publicStatus(JSONObject(NativeHost.status()))
    private fun publicStatus(state: JSONObject): JSONObject {
        return JSONObject().apply {
            for (key in listOf("ok", "state", "code", "error_category", "environment_id", "transport_drain"))
                if (state.has(key)) put(key, state.get(key))
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
