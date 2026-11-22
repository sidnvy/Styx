package com.styx.host

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var resumed = false
    private var statusPending = false
    private val pollStatus = Runnable { refreshStatus() }
    private lateinit var statusView: TextView
    private lateinit var gateway: EditText
    private lateinit var code: EditText
    private lateinit var label: EditText
    private lateinit var pairButton: Button
    private lateinit var forgetButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Pairing fields must not be captured by remote screen tools or the recent-apps preview.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val settings = getSharedPreferences("settings", MODE_PRIVATE)
        val pad = (20 * resources.displayMetrics.density).toInt()
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        content.addView(TextView(this).apply { text = "Styx Android Host"; textSize = 26f })
        content.addView(TextView(this).apply { text = "Pair this phone with your Gateway, then enable Android control."; textSize = 16f })
        gateway = field("Gateway URL", settings.getString("gateway_url", "") ?: "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        code = field("Invitation short code", "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        label = field("Device name", settings.getString("device_label", Build.MODEL) ?: Build.MODEL, InputType.TYPE_CLASS_TEXT)
        content.addView(gateway); content.addView(code); content.addView(label)
        pairButton = button("Pair phone") {
            val gatewayUrl = gateway.text.toString().trim()
            val invitationCode = code.text.toString().trim()
            val deviceLabel = label.text.toString().trim().ifEmpty { Build.MODEL }
            if (gatewayUrl.isBlank() || invitationCode.isBlank()) {
                statusView.text = "Enter your Gateway URL and invitation short code."
                return@button
            }
            code.text.clear()
            pairButton.isEnabled = false
            forgetButton.isEnabled = false
            statusView.text = "Pairing…"
            settings.edit().putString("gateway_url", gatewayUrl).putString("device_label", deviceLabel).apply()
            worker.execute {
                try {
                    val result = JSONObject(NativeHost.pair(gatewayUrl, invitationCode, deviceLabel, AndroidPlatform(applicationContext)))
                    runOnUiThread {
                        statusView.text = result.toString(2)
                        pairButton.isEnabled = true
                        forgetButton.isEnabled = true
                        if (result.optBoolean("ok", false)) startHost()
                    }
                } catch (error: Exception) {
                    runOnUiThread { pairButton.isEnabled = true; forgetButton.isEnabled = true; statusView.text = "Pairing failed. Check the Gateway address and invitation state." }
                }
            }
        }
        content.addView(pairButton)
        content.addView(button("Enable Android control") { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) })
        content.addView(button("Battery optimization settings") { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) })
        content.addView(button("Start Host") { startHost() })
        content.addView(button("Stop Host") { stopHost(); refreshStatus() })
        content.addView(button("Refresh status") { refreshStatus() })
        forgetButton = button("Forget pairing") { confirmForgetPairing() }
        content.addView(forgetButton)
        statusView = TextView(this).apply { textSize = 14f; setTextIsSelectable(true); setPadding(0, pad, 0, pad) }
        content.addView(statusView)
        val scroll = ScrollView(this).apply { addView(content); fitsSystemWindows = true }
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(scroll)
    }

    override fun onResume() { super.onResume(); resumed = true; if (::statusView.isInitialized) refreshStatus() }
    override fun onPause() { resumed = false; main.removeCallbacks(pollStatus); super.onPause() }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }

    private fun confirmForgetPairing() {
        AlertDialog.Builder(this)
            .setTitle("Forget pairing?")
            .setMessage("Stop this Host and remove its local pairing. A new invitation is required to pair again. Revoke the old device separately on your Gateway.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Forget") { _, _ ->
                stopHost()
                pairButton.isEnabled = false
                forgetButton.isEnabled = false
                statusView.text = "Forgetting pairing…"
                worker.execute {
                    val result = try { JSONObject(NativeHost.forget(AndroidPlatform(applicationContext))) }
                    catch (_: Exception) { JSONObject().put("ok", false).put("error", JSONObject().put("code", "forget_pairing_failed")) }
                    runOnUiThread {
                        code.text.clear()
                        statusView.text = result.toString(2)
                        pairButton.isEnabled = true
                        forgetButton.isEnabled = true
                    }
                }
            }
            .show()
    }

    private fun startHost() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        startForegroundService(Intent(this, HostService::class.java))
        refreshStatus()
    }

    private fun stopHost() {
        // Send STOP action so HostService completes Gateway transport drain before stopping itself.
        startService(Intent(this, HostService::class.java).setAction(HostService.STOP))
    }

    private fun refreshStatus() {
        if (statusPending) return
        statusPending = true
        main.removeCallbacks(pollStatus)
        worker.execute {
            val state = JSONObject(NativeHost.status()).put("permissions", AndroidPlatform.readiness(applicationContext))
            runOnUiThread {
                statusView.text = state.toString(2)
                statusPending = false
                if (resumed) main.postDelayed(pollStatus, 1000)
            }
        }
    }

    private fun field(hintText: String, value: String, type: Int) = EditText(this).apply {
        hint = hintText; inputType = type; setSingleLine(true); setText(value)
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }
    private fun button(title: String, action: () -> Unit) = Button(this).apply { text = title; setOnClickListener { action() } }
}
