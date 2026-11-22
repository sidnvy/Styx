package com.styx.host

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.app.KeyguardManager
import android.hardware.display.DisplayManager
import android.graphics.Point
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import android.util.DisplayMetrics
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.math.roundToInt

/** A platform adapter only: no socket, pairing key, Gateway session, or alternate authorization. */
class StyxAccessibilityService : AccessibilityService() {
    private val main = Handler(Looper.getMainLooper())
    private data class ObservationKey(val caller: String, val displayId: Int)
    private val observations = ConcurrentHashMap<ObservationKey, Observation>()

    // Constructor-owned identity copies stay immutable. Dropping an observation releases
    // its references; recycling a copy could race an action that still references it.
    private data class Target(val path: List<Int>, val viewId: String?, val className: String?,
                              val text: String?, val description: String?, val identity: AccessibilityNodeInfo)
    private data class Observation(val id: String, val displayId: Int, val windowId: Int, val packageName: String?,
                                   val width: Int, val height: Int, val targets: Map<String, Target>)

    override fun onServiceConnected() { instance = this }
    override fun onAccessibilityEvent(event: AccessibilityEvent?) { }
    override fun onInterrupt() { clearObservation() }
    override fun onDestroy() { instance = null; clearObservation(); super.onDestroy() }
    fun clearObservation() { observations.clear() }
    fun releaseCaller(caller: String) { observations.keys.removeIf { it.caller == caller } }

    private fun observation(caller: String, id: String): Observation? =
        observations.entries.firstOrNull { it.key.caller == caller && it.value.id == id }?.value

    private fun display(displayId: Int): Display? =
        getSystemService(DisplayManager::class.java).getDisplay(displayId)

    private fun displaySize(target: Display): Point = Point().also { target.getRealSize(it) }

    // Windows belong to their own displays. rootInActiveWindow may point at a different
    // display after a remote agent switches focus, so it is not safe for display routing.
    private fun rootOnDisplay(displayId: Int): AccessibilityNodeInfo? {
        val windows = windowsOnAllDisplays[displayId] ?: return null
        for (window in windows) {
            if (window.type == AccessibilityWindowInfo.TYPE_APPLICATION) {
                window.root?.let { return it }
            }
        }
        return null
    }

    fun execute(method: String, params: JSONObject): JSONObject {
        check(Looper.myLooper() != Looper.getMainLooper()) { "Platform requests must run off the main thread" }
        if (method == "clear") { clearObservation(); return ok() }
        val caller = params.getString("__caller_id")
        if (method == "release_caller") { releaseCaller(caller); return ok() }
        return when (method) {
            "android_list_displays" -> listDisplays()
            "android_observe" -> observe(caller, params)
            "android_act" -> act(caller, params.getString("observation_id"), params.getJSONObject("action"),
                if (params.has("display_id")) params.getInt("display_id") else null)
            "android_run_steps" -> runSteps(caller, params)
            else -> fail("unsupported_method", "Unknown Android operation.")
        }
    }

    private fun listDisplays(): JSONObject {
        if (getSystemService(KeyguardManager::class.java).isKeyguardLocked)
            return fail("device_locked", "Unlock the phone before inspecting its displays.")
        val displays = JSONArray()
        val allWindows = windowsOnAllDisplays
        for (target in getSystemService(DisplayManager::class.java).displays) {
            val size = displaySize(target)
            val metrics = DisplayMetrics().also { target.getRealMetrics(it) }
            val windows = JSONArray()
            for (window in allWindows[target.displayId].orEmpty()) {
                if (window.type != AccessibilityWindowInfo.TYPE_APPLICATION) continue
                val root = window.root
                val packageName = try { root?.packageName?.toString() } finally { root?.recycle() }
                val bounds = Rect().also { window.getBoundsInScreen(it) }
                windows.put(JSONObject().put("window_id", window.id)
                    .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
                    .put("package_name", packageName ?: JSONObject.NULL)
                    .put("title", window.title?.toString() ?: JSONObject.NULL)
                    .put("focused", window.isFocused).put("active", window.isActive))
            }
            displays.put(JSONObject().put("display_id", target.displayId)
                .put("name", target.name)
                .put("width", size.x).put("height", size.y)
                .put("density", metrics.density)
                .put("windows", windows))
        }
        return ok().put("displays", displays)
    }

    private fun observe(caller: String, params: JSONObject): JSONObject {
        val started = SystemClock.elapsedRealtime()
        val readiness = AndroidPlatform.readiness(this)
        if (readiness.getBoolean("device_locked")) {
            releaseCaller(caller)
            return fail("device_locked", "Unlock the phone before observing or controlling its apps.").put("permission_state", readiness)
        }
        val displayId = params.optInt("display_id", Display.DEFAULT_DISPLAY)
        if (displayId < 0) return fail("invalid_arguments", "display_id must be nonnegative.")
        val targetDisplay = display(displayId)
            ?: return fail("display_not_found", "The selected Android display no longer exists.")
        val maxNodes = params.optInt("max_nodes", 500)
        val maxDimension = params.optInt("max_dimension", 1280)
        if (maxNodes < 1 || maxDimension < 1) return fail("invalid_arguments", "max_nodes and max_dimension must be positive.")
        // Content-change events can arrive after an action returns. Fetch this observation
        // from current views instead of reusing the previous tree's cached nodes.
        val refreshNodes = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU
        if (!refreshNodes) clearCache()
        val root = rootOnDisplay(displayId) ?: return fail("no_active_window", "The selected display has no accessible app window.")
        val size = displaySize(targetDisplay)
        val metrics = DisplayMetrics().also { targetDisplay.getRealMetrics(it) }
        val id = UUID.randomUUID().toString()
        val targets = linkedMapOf<String, Target>()
        val nodes = JSONArray()
        val queue = ArrayDeque<Pair<AccessibilityNodeInfo, List<Int>>>()
        queue.add(root to emptyList())
        var truncated = false
        val windowId = root.windowId
        val packageName = root.packageName?.toString()
        while (queue.isNotEmpty()) {
            val (node, path) = queue.removeFirst()
            try {
                if (targets.size >= maxNodes) { truncated = true; continue }
                if (refreshNodes && !node.refresh()) continue
                val bounds = Rect().also { node.getBoundsInScreen(it) }
                val nodeId = "n${targets.size}"
                val text = if (node.isPassword) null else node.text?.toString()
                val description = if (node.isPassword) null else node.contentDescription?.toString()
                targets[nodeId] = Target(path, node.viewIdResourceName, node.className?.toString(), text, description, AccessibilityNodeInfo(node))
                nodes.put(JSONObject()
                    .put("node_id", nodeId)
                    .put("view_id", node.viewIdResourceName ?: JSONObject.NULL)
                    .put("class_name", node.className?.toString() ?: JSONObject.NULL)
                    .put("text", text ?: JSONObject.NULL)
                    .put("description", description ?: JSONObject.NULL)
                    .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
                    .put("clickable", node.isClickable).put("long_clickable", node.isLongClickable)
                    .put("editable", node.isEditable).put("scrollable", node.isScrollable)
                    .put("enabled", node.isEnabled).put("visible", node.isVisibleToUser)
                    .put("focused", node.isFocused).put("password", node.isPassword))
                for (index in 0 until node.childCount) {
                    node.getChild(index)?.let { queue.add(it to (path + index)) }
                }
            } finally { node.recycle() }
        }
        val current = Observation(id, displayId, windowId, packageName, size.x, size.y, targets)
        observations[ObservationKey(caller, displayId)] = current
        val result = ok().put("observation_id", id).put("display_id", displayId).put("package_name", packageName ?: JSONObject.NULL)
            .put("window_id", windowId).put("permission_state", readiness)
            .put("display", JSONObject().put("width", size.x).put("height", size.y)
                .put("density", metrics.density))
            .put("truncated", truncated)
        if (params.optBoolean("include_tree", true)) result.put("nodes", nodes)
        if (params.optBoolean("screenshot", false)) {
            val capture = screenshot(displayId, maxDimension)
            if (capture.optBoolean("ok", false)) result.put("screenshot", capture.getJSONObject("screenshot"))
            else result.put("screenshot_error", capture.getJSONObject("error"))
        }
        return result.put("duration_ms", SystemClock.elapsedRealtime() - started)
    }

    private fun act(caller: String, observationId: String, action: JSONObject, requestedDisplayId: Int? = null): JSONObject {
        if (getSystemService(KeyguardManager::class.java).isKeyguardLocked) return fail("device_locked", "Unlock the phone before controlling its apps.")
        val observed = observation(caller, observationId)
            ?: return fail("stale_observation", "Observe the current screen before acting.")
        if (requestedDisplayId != null && requestedDisplayId != observed.displayId)
            return fail("stale_observation", "The observation belongs to a different display.")
        val root = rootOnDisplay(observed.displayId)
            ?: return fail("no_active_window", "The observed display has no accessible app window.")
        try {
            if (root.windowId != observed.windowId || root.packageName?.toString() != observed.packageName) {
                return fail("stale_observation", "The active window changed; observe it before acting.")
            }
            return when (action.getString("type")) {
                "back", "home", "recents" -> {
                    // performGlobalAction has no display target: never accidentally navigate
                    // the physical screen when a secondary display was requested.
                    if (observed.displayId != Display.DEFAULT_DISPLAY)
                        fail("unsupported_action", "Global navigation is only supported on the default display.")
                    else when (action.getString("type")) {
                        "back" -> globalAction(GLOBAL_ACTION_BACK)
                        "home" -> globalAction(GLOBAL_ACTION_HOME)
                        else -> globalAction(GLOBAL_ACTION_RECENTS)
                    }
                }
                "tap", "swipe" -> gesture(caller, observed, action)
                "click", "long_click", "set_text", "scroll_forward", "scroll_backward" -> nodeAction(root, observed, action)
                else -> fail("unsupported_action", "Unknown Android action.")
            }
        } finally { root.recycle() }
    }

    private fun nodeAction(root: AccessibilityNodeInfo, observed: Observation, action: JSONObject): JSONObject {
        val target = observed.targets[action.getString("node_id")]
            ?: return fail("unknown_node", "The node does not belong to this observation.")
        var node = AccessibilityNodeInfo.obtain(root)
        try {
            for (index in target.path) {
                val child = node.getChild(index) ?: return fail("stale_node", "The observed node is no longer present.")
                node.recycle(); node = child
            }
            if (!node.refresh()) return fail("stale_node", "The observed node is no longer present.")
            val text = if (node.isPassword) null else node.text?.toString()
            val description = if (node.isPassword) null else node.contentDescription?.toString()
            if (node != target.identity || node.viewIdResourceName != target.viewId ||
                node.className?.toString() != target.className || text != target.text || description != target.description) {
                return fail("stale_node", "The observed node changed; observe it before acting.")
            }
            if (!node.isVisibleToUser || !node.isEnabled) return fail("node_not_ready", "The observed node is not visible and enabled.")
            val arguments = Bundle()
            val actionId = when (action.getString("type")) {
                "click" -> AccessibilityNodeInfo.ACTION_CLICK
                "long_click" -> AccessibilityNodeInfo.ACTION_LONG_CLICK
                "set_text" -> {
                    if (!node.isEditable) return fail("node_not_editable", "The observed node does not support text entry.")
                    arguments.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, action.getString("text"))
                    AccessibilityNodeInfo.ACTION_SET_TEXT
                }
                "scroll_forward" -> AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
                "scroll_backward" -> AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
                else -> return fail("unsupported_action", "Unknown node action.")
            }
            return if (node.performAction(actionId, arguments)) ok().put("performed", true)
                else fail("action_not_performed", "Android did not perform the requested node action.")
        } finally { node.recycle() }
    }

    private fun globalAction(action: Int): JSONObject = if (performGlobalAction(action)) ok().put("performed", true)
        else fail("action_not_performed", "Android did not perform the navigation action.")

    private fun gesture(caller: String, observed: Observation, action: JSONObject): JSONObject {
        val size = display(observed.displayId)?.let(::displaySize)
        if (size == null || size.x != observed.width || size.y != observed.height) {
            return fail("stale_observation", "The display dimensions changed; observe before tapping.")
        }
        val x = action.getDouble("x").toFloat()
        val y = action.getDouble("y").toFloat()
        val swipe = action.getString("type") == "swipe"
        val endX = if (swipe) action.getDouble("end_x").toFloat() else x
        val endY = if (swipe) action.getDouble("end_y").toFloat() else y
        if (!x.isFinite() || !y.isFinite() || !endX.isFinite() || !endY.isFinite() ||
            x < 0 || x >= observed.width || y < 0 || y >= observed.height ||
            endX < 0 || endX >= observed.width || endY < 0 || endY >= observed.height) {
            return fail("invalid_arguments", "Gesture points must be inside the observed display.")
        }
        val duration = action.optLong("duration_ms", if (swipe) 300 else 50)
        if (duration <= 0 || duration > GestureDescription.getMaxGestureDuration()) return fail("invalid_arguments", "Unsupported gesture duration.")
        val path = Path().apply { moveTo(x, y); if (swipe) lineTo(endX, endY) }
        val gesture = GestureDescription.Builder().setDisplayId(observed.displayId)
            .addStroke(GestureDescription.StrokeDescription(path, 0, duration)).build()
        val done = CountDownLatch(1)
        var result: JSONObject? = null
        main.post {
            if (observations[ObservationKey(caller, observed.displayId)]?.id != observed.id) {
                result = fail("stale_observation", "The observation was released before gesture dispatch.")
                done.countDown()
                return@post
            }
            val accepted = dispatchGesture(gesture, object : GestureResultCallback() {
                override fun onCompleted(gestureDescription: GestureDescription?) { result = ok().put("performed", true); done.countDown() }
                override fun onCancelled(gestureDescription: GestureDescription?) { result = fail("gesture_cancelled", "Android cancelled the gesture; observe its effect.", true); done.countDown() }
            }, main)
            if (!accepted) { result = fail("action_not_performed", "Android did not accept the gesture."); done.countDown() }
        }
        return if (done.await(duration + 5000, TimeUnit.MILLISECONDS)) result!!
            else fail("operation_timeout", "The gesture outcome is unknown; observe before continuing.", true)
    }

    private fun screenshot(displayId: Int, maxDimension: Int): JSONObject {
        val done = CountDownLatch(1)
        var result: JSONObject? = null
        takeScreenshot(displayId, { runnable -> runnable.run() }, object : TakeScreenshotCallback {
            override fun onSuccess(screenshot: ScreenshotResult) {
                val buffer = screenshot.hardwareBuffer
                try {
                    val hardware = Bitmap.wrapHardwareBuffer(buffer, screenshot.colorSpace)
                        ?: throw IllegalStateException("No screenshot bitmap")
                    val bitmap = hardware.copy(Bitmap.Config.ARGB_8888, false)
                    hardware.recycle()
                    val scale = minOf(1.0, maxDimension.toDouble() / max(bitmap.width, bitmap.height))
                    val output = if (scale < 1) Bitmap.createScaledBitmap(bitmap, max(1, (bitmap.width * scale).roundToInt()), max(1, (bitmap.height * scale).roundToInt()), true) else bitmap
                    val bytes = ByteArrayOutputStream().also { output.compress(Bitmap.CompressFormat.JPEG, 80, it) }.toByteArray()
                    result = ok().put("screenshot", JSONObject().put("mime_type", "image/jpeg")
                        .put("data", Base64.encodeToString(bytes, Base64.NO_WRAP)).put("width", output.width).put("height", output.height))
                    if (output !== bitmap) output.recycle()
                    bitmap.recycle()
                } catch (error: Exception) {
                    result = fail("screenshot_failed", "Android could not encode the screenshot.")
                } finally { buffer.close(); done.countDown() }
            }
            override fun onFailure(errorCode: Int) {
                val code = when (errorCode) {
                    ERROR_TAKE_SCREENSHOT_SECURE_WINDOW -> "secure_window"
                    ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT -> "screenshot_rate_limited"
                    ERROR_TAKE_SCREENSHOT_NO_ACCESSIBILITY_ACCESS -> "permission_not_ready"
                    else -> "screenshot_failed"
                }
                result = fail(code, "Android screenshot request failed (code $errorCode).")
                done.countDown()
            }
        })
        return if (done.await(5, TimeUnit.SECONDS)) result!! else fail("screenshot_timeout", "Android did not return a screenshot.")
    }

    private fun runSteps(caller: String, params: JSONObject): JSONObject {
        val id = params.getString("observation_id")
        val observed = observation(caller, id)
            ?: return fail("stale_observation", "Observe the current screen before acting.")
        val displayId = if (params.has("display_id")) params.getInt("display_id") else observed.displayId
        if (displayId != observed.displayId)
            return fail("stale_observation", "The observation belongs to a different display.")
        val steps = params.getJSONArray("steps")
        val results = JSONArray()
        var completed = 0
        var failure: JSONObject? = null
        for (index in 0 until steps.length()) {
            val result = try {
                act(caller, id, steps.getJSONObject(index), displayId)
            } catch (error: JSONException) {
                fail("invalid_arguments", "Invalid Android step.")
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                fail("operation_interrupted", "Android operation was interrupted; observe before issuing another action.", true)
            } catch (error: Exception) {
                fail("android_operation_failed", "Android could not complete this step; observe the current state.", true)
            }
            results.put(result)
            if (!result.optBoolean("ok", false)) { failure = result.getJSONObject("error"); break }
            completed++
        }
        val response = JSONObject().put("ok", failure == null).put("completed_steps", completed).put("results", results)
        if (failure != null) response.put("error", failure).put("failed_step", completed)
        if (params.optBoolean("observe_after", false)) response.put("observation", observe(caller, JSONObject().put("display_id", displayId)))
        return response
    }

    private fun ok() = JSONObject().put("ok", true)
    private fun fail(code: String, message: String, uncertain: Boolean = false) = AndroidPlatform.failure(code, message, uncertain)
    companion object { @Volatile var instance: StyxAccessibilityService? = null; private set }
}
