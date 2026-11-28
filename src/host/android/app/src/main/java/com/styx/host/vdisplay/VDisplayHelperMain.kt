package com.styx.host.vdisplay

import android.annotation.SuppressLint
import android.content.AttributionSource
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.hardware.display.VirtualDisplayConfig
import android.hardware.input.InputManager
import android.media.ImageReader
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.Parcelable
import android.os.Process
import android.os.SharedMemory
import android.os.SystemClock
import android.system.OsConstants
import android.view.Display
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.math.roundToInt
import kotlin.system.exitProcess

/**
 * Standalone UID-2000 (shell) app_process daemon providing Styx Tier 2 virtual display
 * lifecycle, ImageReader capture over SharedMemory, display-scoped input injection, and
 * shell `cmd activity start-activity --display` launching.
 */
object VDisplayHelperMain {
    private const val VIRTUAL_DISPLAY_FLAG_PUBLIC = 1 shl 0
    private const val VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY = 1 shl 3
    private const val VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH = 1 shl 6
    private const val VIRTUAL_DISPLAY_FLAG_ROTATES_WITH_CONTENT = 1 shl 7
    private const val VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL = 1 shl 8
    private const val VIRTUAL_DISPLAY_FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS = 1 shl 9
    private const val VIRTUAL_DISPLAY_FLAG_TRUSTED = 1 shl 10
    private const val VIRTUAL_DISPLAY_FLAG_OWN_DISPLAY_GROUP = 1 shl 11
    private const val VIRTUAL_DISPLAY_FLAG_OWN_FOCUS = 1 shl 14
    private const val DISPLAY_IME_POLICY_HIDE = 2
    private const val INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH = 2
    private const val STYX_HOST_PACKAGE = "com.styx.host"

    private lateinit var shellContext: Context
    private lateinit var captureThread: HandlerThread
    private lateinit var captureHandler: Handler

    private data class ManagedDisplay(
        val displayId: Int,
        val name: String,
        val width: Int,
        val height: Int,
        val densityDpi: Int,
        val virtualDisplay: VirtualDisplay,
        val imageReader: ImageReader,
        val frameLock: Object = Object(),
        var latestBitmap: Bitmap? = null,
    )

    private val displays = ConcurrentHashMap<Int, ManagedDisplay>()
    private val displayLock = Any()

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.contains("--help") || args.contains("-h")) {
            println("usage: app_process / com.styx.host.vdisplay.VDisplayHelperMain [--self-test]")
            exitProcess(0)
        }
        bootstrap()
        if (args.contains("--self-test")) {
            val report = runSelfTest()
            println(report.toString(2))
            cleanupAllDisplays()
            exitProcess(if (report.optBoolean("ok", false)) 0 else 1)
        }

        Runtime.getRuntime().addShutdownHook(Thread {
            log("shutting down, releasing ${displays.size} managed displays")
            cleanupAllDisplays()
        })

        val binder = HelperBinder()
        val selfToken = Binder()
        log("started pid=${Process.myPid()} uid=${Process.myUid()}")
        deliveryLoop(binder, selfToken)
    }

    @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
    private fun bootstrap() {
        runCatching {
            val vmRuntime = Class.forName("dalvik.system.VMRuntime")
            val getRuntime = vmRuntime.getDeclaredMethod("getRuntime")
            val runtime = getRuntime.invoke(null)
            val setExemptions = vmRuntime.getDeclaredMethod("setHiddenApiExemptions", Array<String>::class.java)
            setExemptions.invoke(runtime, arrayOf("L"))
        }
        runCatching {
            Process::class.java.getDeclaredMethod("setArgV0", String::class.java)
                .invoke(null, "styx-vdisplay")
        }
        if (Looper.getMainLooper() == null) {
            @Suppress("DEPRECATION")
            Looper.prepareMainLooper()
        }
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val activityThread = activityThreadClass.getDeclaredMethod("systemMain").invoke(null)
        val systemContext = activityThreadClass.getDeclaredMethod("getSystemContext")
            .invoke(activityThread) as Context
        shellContext = try {
            systemContext.createPackageContext("com.android.shell", Context.CONTEXT_IGNORE_SECURITY)
        } catch (_: Throwable) {
            systemContext
        }
        captureThread = HandlerThread("styx-vdisplay-capture").apply { start() }
        captureHandler = Handler(captureThread.looper)
    }

    private fun deliveryLoop(helperBinder: IBinder, selfToken: IBinder) {
        var announcedConnected = false
        while (true) {
            try {
                val appToken = registerWithHost(helperBinder, selfToken)
                if (!announcedConnected) {
                    log("binder to $STYX_HOST_PACKAGE: ok")
                    announcedConnected = true
                }
                val deadLatch = CountDownLatch(1)
                appToken.linkToDeath({ deadLatch.countDown() }, 0)
                if (!appToken.isBinderAlive) {
                    deadLatch.countDown()
                }
                deadLatch.await()
                log("$STYX_HOST_PACKAGE exited; waiting to re-register binder")
                announcedConnected = false
            } catch (error: Throwable) {
                if (announcedConnected) {
                    announcedConnected = false
                }
                log("binder delivery pending: ${error.message ?: error.javaClass.simpleName}")
                Thread.sleep(2000)
                continue
            }
            Thread.sleep(1000)
        }
    }

    @SuppressLint("PrivateApi")
    private fun registerWithHost(helperBinder: IBinder, selfToken: IBinder): IBinder {
        val extras = Bundle().apply {
            putBinder(VDisplayProtocol.EXTRA_BINDER, helperBinder)
        }
        val amClass = Class.forName("android.app.ActivityManager")
        val am = amClass.getDeclaredMethod("getService").invoke(null)
        if (am != null) {
            val iamClass = am.javaClass
            val getExternal = iamClass.getMethod(
                "getContentProviderExternal",
                String::class.java,
                Int::class.javaPrimitiveType,
                IBinder::class.java,
                String::class.java,
            )
            val holder = getExternal.invoke(
                am,
                VDisplayProtocol.PROVIDER_AUTHORITY,
                0,
                selfToken,
                "styx-vdisplay",
            )
            if (holder != null) {
                try {
                    val providerField = holder.javaClass.getField("provider")
                    val provider = providerField.get(holder)
                        ?: throw IllegalStateException("$STYX_HOST_PACKAGE provider binder null")
                    val resultBundle = invokeProviderCall(provider, extras)
                    return resultBundle?.getBinder(VDisplayProtocol.EXTRA_APP_TOKEN)
                        ?: throw IllegalStateException("Host did not return app_token")
                } finally {
                    runCatching {
                        iamClass.getMethod(
                            "removeContentProviderExternalAsUser",
                            String::class.java,
                            IBinder::class.java,
                            Int::class.javaPrimitiveType,
                        ).invoke(am, VDisplayProtocol.PROVIDER_AUTHORITY, selfToken, 0)
                    }.onFailure {
                        runCatching {
                            iamClass.getMethod(
                                "removeContentProviderExternal",
                                String::class.java,
                                IBinder::class.java,
                            ).invoke(am, VDisplayProtocol.PROVIDER_AUTHORITY, selfToken)
                        }
                    }
                }
            }
        }
        val resultBundle = shellContext.contentResolver.call(
            VDisplayProtocol.PROVIDER_AUTHORITY,
            VDisplayProtocol.METHOD_REGISTER_BINDER,
            null,
            extras,
        )
        return resultBundle?.getBinder(VDisplayProtocol.EXTRA_APP_TOKEN)
            ?: throw IllegalStateException("$STYX_HOST_PACKAGE provider unavailable")
    }

    @SuppressLint("PrivateApi")
    private fun invokeProviderCall(provider: Any, extras: Bundle): Bundle? {
        val providerClass = provider.javaClass
        // API 31+ signature: call(AttributionSource, String authority, String method, String arg, Bundle extras)
        runCatching {
            val attrSourceClass = AttributionSource::class.java
            val callMethod = providerClass.getMethod(
                "call",
                attrSourceClass,
                String::class.java,
                String::class.java,
                String::class.java,
                Bundle::class.java,
            )
            val attrSource = AttributionSource.Builder(Process.myUid())
                .setPackageName("com.android.shell")
                .build()
            return callMethod.invoke(
                provider,
                attrSource,
                VDisplayProtocol.PROVIDER_AUTHORITY,
                VDisplayProtocol.METHOD_REGISTER_BINDER,
                null,
                extras,
            ) as? Bundle
        }.onFailure { err ->
            val cause = err.cause
            if (cause is SecurityException || cause is IllegalArgumentException) {
                throw cause
            }
        }

        // Fallback API 30 signature: call(String callingPkg, String attributionTag, String authority, String method, String arg, Bundle extras)
        val callLegacy = providerClass.getMethod(
            "call",
            String::class.java,
            String::class.java,
            String::class.java,
            String::class.java,
            String::class.java,
            Bundle::class.java,
        )
        return callLegacy.invoke(
            provider,
            "com.android.shell",
            null,
            VDisplayProtocol.PROVIDER_AUTHORITY,
            VDisplayProtocol.METHOD_REGISTER_BINDER,
            null,
            extras,
        ) as? Bundle
    }

    private fun allowedHostUid(): Int? = runCatching {
        shellContext.packageManager.getPackageUid(STYX_HOST_PACKAGE, 0)
    }.getOrNull()

    private class HelperBinder : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code == INTERFACE_TRANSACTION) {
                reply?.writeString(VDisplayProtocol.INTERFACE_DESCRIPTOR)
                return true
            }
            if (code != VDisplayProtocol.TX_CALL) {
                return super.onTransact(code, data, reply, flags)
            }
            data.enforceInterface(VDisplayProtocol.INTERFACE_DESCRIPTOR)
            val callingUid = getCallingUid()
            val hostUid = allowedHostUid()
            val authorized = callingUid == Process.SHELL_UID ||
                callingUid == Process.ROOT_UID ||
                (hostUid != null && callingUid == hostUid)
            if (!authorized) {
                throw SecurityException("Unauthorized caller UID $callingUid for VDisplayHelper")
            }

            val req = JSONObject(data.readString() ?: "{}")
            val method = req.optString("method")
            val params = req.optJSONObject("params") ?: JSONObject()
            val (response, jpegBytes) = dispatch(method, params)

            if (jpegBytes != null) {
                val shm = SharedMemory.create("styx-vd-frame", jpegBytes.size)
                try {
                    val buf = shm.mapReadWrite()
                    try {
                        buf.put(jpegBytes)
                    } finally {
                        SharedMemory.unmap(buf)
                    }
                    shm.setProtect(OsConstants.PROT_READ)
                    response.put("byte_length", jpegBytes.size)
                    reply?.writeNoException()
                    reply?.writeString(response.toString())
                    reply?.writeInt(1)
                    shm.writeToParcel(reply!!, Parcelable.PARCELABLE_WRITE_RETURN_VALUE)
                } finally {
                    shm.close()
                }
            } else {
                reply?.writeNoException()
                reply?.writeString(response.toString())
                reply?.writeInt(0)
            }
            return true
        }
    }

    private fun dispatch(method: String, params: JSONObject): Pair<JSONObject, ByteArray?> {
        return try {
            when (method) {
                "ping" -> JSONObject()
                    .put("ok", true)
                    .put("version", VDisplayProtocol.PROTOCOL_VERSION)
                    .put("pid", Process.myPid())
                    .put("uid", Process.myUid())
                    .put("managed_display_ids", JSONArray(displays.keys.sorted())) to null

                "list_displays" -> JSONObject()
                    .put("ok", true)
                    .put("managed_display_ids", JSONArray(displays.keys.sorted())) to null

                "create_display" -> createDisplay(params) to null
                "destroy_display" -> destroyDisplay(params) to null
                "launch_app" -> launchApp(params) to null
                "capture_display" -> captureDisplay(params)
                "inject_key" -> injectKey(params) to null
                "inject_touch" -> injectTouch(params) to null
                else -> failure("unsupported_method", "Unknown helper method: $method") to null
            }
        } catch (error: Throwable) {
            failure(
                "vdisplay_helper_error",
                "Helper operation '$method' failed: ${error.message ?: error.javaClass.simpleName}",
            ) to null
        }
    }

    private fun createDisplay(params: JSONObject): JSONObject {
        val name = params.optString("name", "styx-agent").ifBlank { "styx-agent" }
        val width = params.optInt("width", 1080)
        val height = params.optInt("height", 2340)
        val densityDpi = params.optInt("density_dpi", 420)
        if (!VDisplayProtocol.DISPLAY_NAME_REGEX.matches(name)) {
            return failure("invalid_arguments", "Display name must match [a-zA-Z0-9._-]{1,48}.")
        }
        if (width !in 320..2160 || height !in 480..3840 || densityDpi !in 120..640) {
            return failure("invalid_arguments", "Display geometry out of supported bounds.")
        }

        synchronized(displayLock) {
            if (displays.size >= VDisplayProtocol.MAX_MANAGED_DISPLAYS) {
                return failure(
                    "display_limit_reached",
                    "At most ${VDisplayProtocol.MAX_MANAGED_DISPLAYS} managed virtual displays may exist concurrently.",
                )
            }

            val reader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
            val holder = arrayOfNulls<ManagedDisplay>(1)
            reader.setOnImageAvailableListener({ r ->
                val managed = holder[0] ?: return@setOnImageAvailableListener
                val image = runCatching { r.acquireLatestImage() }.getOrNull() ?: return@setOnImageAvailableListener
                image.use { img ->
                    val plane = img.planes[0]
                    val buffer = plane.buffer
                    val pixelStride = plane.pixelStride
                    val rowStride = plane.rowStride
                    val rowPadding = rowStride - pixelStride * width
                    val bmpWidth = if (pixelStride > 0) width + rowPadding / pixelStride else width
                    val raw = Bitmap.createBitmap(bmpWidth, height, Bitmap.Config.ARGB_8888)
                    raw.copyPixelsFromBuffer(buffer)
                    val frame = if (bmpWidth != width) {
                        val cropped = Bitmap.createBitmap(raw, 0, 0, width, height)
                        raw.recycle()
                        cropped
                    } else {
                        raw
                    }
                    synchronized(managed.frameLock) {
                        managed.latestBitmap?.recycle()
                        managed.latestBitmap = frame
                        managed.frameLock.notifyAll()
                    }
                }
            }, captureHandler)

            val fullFlags = VIRTUAL_DISPLAY_FLAG_PUBLIC or
                VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY or
                VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH or
                VIRTUAL_DISPLAY_FLAG_ROTATES_WITH_CONTENT or
                VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL or
                VIRTUAL_DISPLAY_FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS or
                VIRTUAL_DISPLAY_FLAG_TRUSTED or
                VIRTUAL_DISPLAY_FLAG_OWN_DISPLAY_GROUP or
                VIRTUAL_DISPLAY_FLAG_OWN_FOCUS

            val minimalFlags = VIRTUAL_DISPLAY_FLAG_PUBLIC or
                VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY or
                VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH or
                VIRTUAL_DISPLAY_FLAG_ROTATES_WITH_CONTENT or
                VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL or
                VIRTUAL_DISPLAY_FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS or
                VIRTUAL_DISPLAY_FLAG_TRUSTED

            var vd: VirtualDisplay? = null
            try {
                vd = createVirtualDisplayWithFallback(name, width, height, densityDpi, reader, fullFlags, minimalFlags)
                val displayId = vd.display.displayId
                val managed = ManagedDisplay(displayId, name, width, height, densityDpi, vd, reader)
                holder[0] = managed
                displays[displayId] = managed
                configureDisplayImePolicy(displayId)
                log("created virtual display id=$displayId name=$name ${width}x${height}@$densityDpi")
                return JSONObject()
                    .put("ok", true)
                    .put("display_id", displayId)
                    .put("name", name)
                    .put("width", width)
                    .put("height", height)
                    .put("density_dpi", densityDpi)
                    .put("managed", true)
            } catch (error: Throwable) {
                runCatching { vd?.release() }
                runCatching { reader.close() }
                throw error
            }
        }
    }

    @SuppressLint("PrivateApi")
    private fun createVirtualDisplayWithFallback(
        name: String,
        width: Int,
        height: Int,
        densityDpi: Int,
        reader: ImageReader,
        fullFlags: Int,
        minimalFlags: Int,
    ): VirtualDisplay {
        val dm = shellContext.getSystemService(DisplayManager::class.java)
        var lastError: Throwable? = null
        for (flags in listOf(fullFlags, minimalFlags)) {
            val config = VirtualDisplayConfig.Builder(name, width, height, densityDpi)
                .setSurface(reader.surface)
                .setFlags(flags)
                .build()
            try {
                val direct = dm.createVirtualDisplay(config, captureHandler, null)
                if (direct != null) return direct
            } catch (err: Throwable) {
                lastError = err
            }
            // Fallback for ROM/Android 17 attribution quirks via DisplayManagerGlobal.
            try {
                val dmgClass = Class.forName("android.hardware.display.DisplayManagerGlobal")
                val dmg = dmgClass.getDeclaredMethod("getInstance").invoke(null)
                val cbClass = Class.forName("android.hardware.display.VirtualDisplay\$Callback")
                val method = dmgClass.methods.firstOrNull {
                    it.name == "createVirtualDisplay" && it.parameterCount == 5 &&
                        it.parameterTypes[0] == Context::class.java
                }
                if (method != null) {
                    val result = method.invoke(
                        dmg,
                        shellContext,
                        null,
                        config,
                        Proxy.newProxyInstance(cbClass.classLoader, arrayOf(cbClass)) { _, _, _ -> null },
                        null,
                    ) as? VirtualDisplay
                    if (result != null) return result
                }
            } catch (err: Throwable) {
                lastError = err
            }
        }
        throw lastError ?: IllegalStateException("createVirtualDisplay returned null")
    }

    @SuppressLint("PrivateApi")
    private fun configureDisplayImePolicy(displayId: Int) {
        runCatching {
            val wmgClass = Class.forName("android.view.WindowManagerGlobal")
            val wm = wmgClass.getDeclaredMethod("getWindowManagerService").invoke(null) ?: return
            wm.javaClass.getMethod(
                "setDisplayImePolicy",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            ).invoke(wm, displayId, DISPLAY_IME_POLICY_HIDE)
        }
    }

    private fun destroyDisplay(params: JSONObject): JSONObject {
        val displayId = params.optInt("display_id", -1)
        if (displayId <= 0) {
            return failure("invalid_arguments", "display_id must be a positive managed virtual display ID.")
        }
        synchronized(displayLock) {
            val managed = displays.remove(displayId)
                ?: return failure("display_not_found", "Display $displayId is not a Styx-managed virtual display.")
            releaseManagedDisplay(managed)
            log("destroyed virtual display id=$displayId")
            return JSONObject()
                .put("ok", true)
                .put("display_id", displayId)
                .put("destroyed", true)
        }
    }

    private fun releaseManagedDisplay(managed: ManagedDisplay) {
        runCatching { managed.virtualDisplay.release() }
        runCatching { managed.imageReader.close() }
        synchronized(managed.frameLock) {
            managed.latestBitmap?.recycle()
            managed.latestBitmap = null
        }
    }

    private fun cleanupAllDisplays() {
        synchronized(displayLock) {
            val items = displays.values.toList()
            displays.clear()
            for (item in items) {
                releaseManagedDisplay(item)
            }
        }
    }

    private fun launchApp(params: JSONObject): JSONObject {
        val pkg = params.optString("package_name", "")
        if (!VDisplayProtocol.PACKAGE_NAME_REGEX.matches(pkg)) {
            return failure("invalid_arguments", "Invalid Android package_name.")
        }
        val activity = params.optString("activity", "").ifBlank { null }
        if (activity != null && !VDisplayProtocol.ACTIVITY_NAME_REGEX.matches(activity)) {
            return failure("invalid_arguments", "Invalid Android activity class name.")
        }
        val displayId = params.optInt("display_id", Display.DEFAULT_DISPLAY)
        if (displayId < 0) {
            return failure("invalid_arguments", "display_id must be nonnegative.")
        }
        val dm = shellContext.getSystemService(DisplayManager::class.java)
        if (dm.getDisplay(displayId) == null) {
            return failure("display_not_found", "Target Android display $displayId does not exist.")
        }
        val clearTask = params.optBoolean("clear_task", false)

        val component = if (activity != null) {
            if (activity.contains('/')) activity
            else if (activity.startsWith(".")) "$pkg/$pkg$activity"
            else if (activity.contains('.')) "$pkg/$activity"
            else "$pkg/$pkg.$activity"
        } else {
            resolveLauncherComponent(pkg)
                ?: return failure("package_not_launchable", "No launchable launcher activity found for $pkg.")
        }

        val flagsHex = if (clearTask) "0x10008000" else "0x10000000"
        val cmd = listOf(
            "/system/bin/cmd",
            "activity",
            "start-activity",
            "--user",
            "0",
            "--display",
            displayId.toString(),
            "-W",
            "-n",
            component,
            "-f",
            flagsHex,
        )
        val exec = runCommand(cmd, timeoutSec = 10)
        if (exec.exitCode != 0 || exec.output.contains("Error:", ignoreCase = true) ||
            exec.output.contains("Exception", ignoreCase = false)
        ) {
            return failure(
                "launch_failed",
                "Failed to launch $component on display $displayId: ${exec.output.trim().take(240)}",
            )
        }
        return JSONObject()
            .put("ok", true)
            .put("package_name", pkg)
            .put("component", component)
            .put("display_id", displayId)
            .put("launched", true)
    }

    private fun resolveLauncherComponent(pkg: String): String? {
        runCatching {
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
                `package` = pkg
            }
            val resolved = shellContext.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            val info = resolved?.activityInfo
            if (info != null) {
                return "${info.packageName}/${info.name}"
            }
        }
        val exec = runCommand(
            listOf(
                "/system/bin/cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-c",
                "android.intent.category.LAUNCHER",
                pkg,
            ),
            timeoutSec = 5,
        )
        if (exec.exitCode != 0) return null
        return exec.output.lineSequence()
            .map { it.trim() }
            .lastOrNull { it.contains('/') && !it.startsWith("No activity", ignoreCase = true) }
    }

    private fun captureDisplay(params: JSONObject): Pair<JSONObject, ByteArray?> {
        val displayId = params.optInt("display_id", -1)
        val maxDimension = params.optInt("max_dimension", 1280).coerceIn(128, 4096)
        val managed = displays[displayId]
            ?: return failure("display_not_found", "Display $displayId is not a Styx-managed virtual display.") to null

        var copy: Bitmap? = null
        val deadline = SystemClock.elapsedRealtime() + 350L
        synchronized(managed.frameLock) {
            while (managed.latestBitmap == null) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) break
                managed.frameLock.wait(remaining)
            }
            copy = managed.latestBitmap?.copy(Bitmap.Config.ARGB_8888, false)
        }
        val bitmap = copy
            ?: return failure("screenshot_timeout", "Virtual display $displayId has not produced a rendered frame yet.") to null

        try {
            val scale = minOf(1.0, maxDimension.toDouble() / max(bitmap.width, bitmap.height))
            val output = if (scale < 1.0) {
                Bitmap.createScaledBitmap(
                    bitmap,
                    max(1, (bitmap.width * scale).roundToInt()),
                    max(1, (bitmap.height * scale).roundToInt()),
                    true,
                )
            } else {
                bitmap
            }
            try {
                val bytes = ByteArrayOutputStream().also {
                    output.compress(Bitmap.CompressFormat.JPEG, 80, it)
                }.toByteArray()
                val header = JSONObject()
                    .put("ok", true)
                    .put("width", output.width)
                    .put("height", output.height)
                    .put("mime_type", "image/jpeg")
                return header to bytes
            } finally {
                if (output !== bitmap) output.recycle()
            }
        } finally {
            bitmap.recycle()
        }
    }

    private fun injectKey(params: JSONObject): JSONObject {
        val displayId = params.optInt("display_id", -1)
        val keyCode = params.optInt("key_code", -1)
        if (displayId < 0) {
            return failure("invalid_arguments", "display_id must be nonnegative.")
        }
        if (keyCode !in VDisplayProtocol.ALLOWED_NAV_KEYCODES) {
            return failure("unsupported_action", "Key code $keyCode is not an allowed navigation key.")
        }
        val now = SystemClock.uptimeMillis()
        val down = KeyEvent(
            now,
            now,
            KeyEvent.ACTION_DOWN,
            keyCode,
            0,
            0,
            KeyCharacterMap.VIRTUAL_KEYBOARD,
            0,
            0,
            InputDevice.SOURCE_KEYBOARD,
        )
        val up = KeyEvent(
            now,
            now + 20L,
            KeyEvent.ACTION_UP,
            keyCode,
            0,
            0,
            KeyCharacterMap.VIRTUAL_KEYBOARD,
            0,
            0,
            InputDevice.SOURCE_KEYBOARD,
        )
        setEventDisplayId(down, displayId)
        setEventDisplayId(up, displayId)
        val okDown = injectInputEvent(down)
        val okUp = injectInputEvent(up)
        return if (okDown && okUp) {
            JSONObject().put("ok", true).put("performed", true)
        } else {
            failure("action_not_performed", "InputManager rejected key injection on display $displayId.", uncertain = true)
        }
    }

    private fun injectTouch(params: JSONObject): JSONObject {
        val displayId = params.optInt("display_id", -1)
        if (displayId < 0) {
            return failure("invalid_arguments", "display_id must be nonnegative.")
        }
        val x = params.optDouble("x", Double.NaN).toFloat()
        val y = params.optDouble("y", Double.NaN).toFloat()
        val endX = params.optDouble("end_x", x.toDouble()).toFloat()
        val endY = params.optDouble("end_y", y.toDouble()).toFloat()
        val durationMs = params.optLong("duration_ms", 50L)
        if (!x.isFinite() || !y.isFinite() || !endX.isFinite() || !endY.isFinite() || durationMs !in 1L..10_000L) {
            return failure("invalid_arguments", "Invalid touch gesture parameters.")
        }
        val downTime = SystemClock.uptimeMillis()
        if (!injectMotion(displayId, downTime, downTime, MotionEvent.ACTION_DOWN, x, y)) {
            return failure("action_not_performed", "InputManager rejected touch down on display $displayId.")
        }
        val isSwipe = x != endX || y != endY || durationMs > 80L
        if (isSwipe) {
            val steps = max(1, (durationMs / 16L).toInt()).coerceAtMost(200)
            for (step in 1 until steps) {
                val frac = step.toFloat() / steps.toFloat()
                val curX = x + (endX - x) * frac
                val curY = y + (endY - y) * frac
                val targetTime = downTime + (durationMs * step) / steps
                val sleepMs = targetTime - SystemClock.uptimeMillis()
                if (sleepMs > 0) Thread.sleep(sleepMs)
                if (!injectMotion(displayId, downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_MOVE, curX, curY)) {
                    return failure("gesture_cancelled", "InputManager interrupted touch move on display $displayId.", uncertain = true)
                }
            }
        }
        val endWait = (downTime + durationMs) - SystemClock.uptimeMillis()
        if (endWait > 0) Thread.sleep(endWait)
        val okUp = injectMotion(displayId, downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_UP, endX, endY)
        return if (okUp) {
            JSONObject().put("ok", true).put("performed", true)
        } else {
            failure("gesture_cancelled", "InputManager failed touch up on display $displayId.", uncertain = true)
        }
    }

    private fun injectMotion(
        displayId: Int,
        downTime: Long,
        eventTime: Long,
        action: Int,
        x: Float,
        y: Float,
    ): Boolean {
        val props = arrayOf(MotionEvent.PointerProperties().apply {
            id = 0
            toolType = MotionEvent.TOOL_TYPE_FINGER
        })
        val coords = arrayOf(MotionEvent.PointerCoords().apply {
            this.x = x
            this.y = y
            pressure = if (action == MotionEvent.ACTION_UP) 0f else 1f
            size = 1f
        })
        val event = MotionEvent.obtain(
            downTime,
            eventTime,
            action,
            1,
            props,
            coords,
            0,
            0,
            1.0f,
            1.0f,
            0,
            0,
            InputDevice.SOURCE_TOUCHSCREEN,
            0,
        )
        return try {
            setEventDisplayId(event, displayId)
            injectInputEvent(event)
        } finally {
            event.recycle()
        }
    }

    @SuppressLint("PrivateApi")
    private fun setEventDisplayId(event: InputEvent, displayId: Int) {
        InputEvent::class.java.getMethod("setDisplayId", Int::class.javaPrimitiveType)
            .invoke(event, displayId)
    }

    @SuppressLint("PrivateApi")
    private fun injectInputEvent(event: InputEvent): Boolean {
        runCatching {
            val imgClass = Class.forName("android.hardware.input.InputManagerGlobal")
            val img = imgClass.getDeclaredMethod("getInstance").invoke(null)
            return imgClass.getMethod(
                "injectInputEvent",
                InputEvent::class.java,
                Int::class.javaPrimitiveType,
            ).invoke(img, event, INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH) as Boolean
        }
        val imClass = InputManager::class.java
        val im = imClass.getDeclaredMethod("getInstance").invoke(null)
        return imClass.getMethod(
            "injectInputEvent",
            InputEvent::class.java,
            Int::class.javaPrimitiveType,
        ).invoke(im, event, INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH) as Boolean
    }

    private data class CommandResult(val exitCode: Int, val output: String)

    private fun runCommand(cmd: List<String>, timeoutSec: Long): CommandResult {
        val process = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val finished = process.waitFor(timeoutSec, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return CommandResult(-1, "command timed out after ${timeoutSec}s")
        }
        val out = process.inputStream.bufferedReader().readText()
        return CommandResult(process.exitValue(), out)
    }

    private fun runSelfTest(): JSONObject {
        val report = JSONObject().put("mode", "self_test")
        var displayId = -1
        try {
            val created = createDisplay(JSONObject()
                .put("name", "styx-selftest")
                .put("width", 1080)
                .put("height", 2340)
                .put("density_dpi", 420))
            report.put("create_display", created)
            if (!created.optBoolean("ok", false)) return report.put("ok", false)
            displayId = created.getInt("display_id")

            val launched = launchApp(JSONObject()
                .put("package_name", "com.android.settings")
                .put("display_id", displayId)
                .put("clear_task", true))
            report.put("launch_app", launched)
            if (!launched.optBoolean("ok", false)) return report.put("ok", false)

            Thread.sleep(1000)
            val (capHeader, capBytes) = captureDisplay(JSONObject()
                .put("display_id", displayId)
                .put("max_dimension", 1280))
            val validJpeg = capBytes != null && capBytes.size > 1000 &&
                capBytes[0] == 0xFF.toByte() && capBytes[1] == 0xD8.toByte()
            val decoded = if (capBytes != null && capBytes.isNotEmpty()) {
                android.graphics.BitmapFactory.decodeByteArray(capBytes, 0, capBytes.size)
            } else {
                null
            }
            var nonBlack = 0
            if (decoded != null) {
                for (y in decoded.height / 5 until decoded.height * 4 / 5 step 8) {
                    for (x in decoded.width / 5 until decoded.width * 4 / 5 step 8) {
                        val px = decoded.getPixel(x, y)
                        if (android.graphics.Color.red(px) > 10 ||
                            android.graphics.Color.green(px) > 10 ||
                            android.graphics.Color.blue(px) > 10
                        ) {
                            nonBlack++
                        }
                    }
                }
                decoded.recycle()
            }
            report.put("capture_display", JSONObject(capHeader.toString())
                .put("byte_length", capBytes?.size ?: 0)
                .put("valid_jpeg", validJpeg)
                .put("non_black_samples", nonBlack))
            if (!capHeader.optBoolean("ok", false) || !validJpeg || nonBlack == 0) {
                return report.put("ok", false)
            }

            val touched = injectTouch(JSONObject()
                .put("display_id", displayId)
                .put("x", 540)
                .put("y", 1170)
                .put("end_x", 540)
                .put("end_y", 1170)
                .put("duration_ms", 50))
            report.put("inject_touch", touched)
            if (!touched.optBoolean("ok", false)) return report.put("ok", false)

            val keyed = injectKey(JSONObject()
                .put("display_id", displayId)
                .put("key_code", KeyEvent.KEYCODE_BACK))
            report.put("inject_key", keyed)
            if (!keyed.optBoolean("ok", false)) return report.put("ok", false)

            val destroyed = destroyDisplay(JSONObject().put("display_id", displayId))
            displayId = -1
            report.put("destroy_display", destroyed)
            return report.put("ok", destroyed.optBoolean("ok", false))
        } catch (error: Throwable) {
            return report.put("ok", false).put("exception", "${error.javaClass.simpleName}: ${error.message}")
        } finally {
            if (displayId > 0) {
                runCatching { destroyDisplay(JSONObject().put("display_id", displayId)) }
            }
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

    private fun log(message: String) {
        println("styx-vdisplay: $message")
    }
}
