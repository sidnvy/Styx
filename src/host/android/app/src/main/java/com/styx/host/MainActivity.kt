package com.styx.host

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
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
    private var busy = false
    private var hostActive = false
    private val pollStatus = Runnable { refreshStatus() }

    private lateinit var statusPill: TextView
    private lateinit var headerSubtitle: TextView

    // Unpaired setup card
    private lateinit var setupCard: LinearLayout
    private lateinit var gatewayInput: EditText
    private lateinit var codeInput: EditText
    private lateinit var labelInput: EditText
    private lateinit var pairButton: Button
    private lateinit var setupMessage: TextView

    // Paired status & controls
    private lateinit var pairedSection: LinearLayout
    private lateinit var gatewayValue: TextView
    private lateinit var deviceValue: TextView
    private lateinit var envIdRow: LinearLayout
    private lateinit var envIdValue: TextView
    private lateinit var issueBanner: TextView
    private lateinit var toggleHostButton: Button

    // Permissions checklist
    private lateinit var accessibilityBadge: TextView
    private lateinit var accessibilityAction: Button
    private lateinit var batteryBadge: TextView
    private lateinit var batteryAction: Button
    private lateinit var forgetButton: Button

    private var darkMode = false
    private var bgColor = 0
    private var cardBg = 0
    private var cardBorder = 0
    private var inputBg = 0
    private var textPrimary = 0
    private var textSecondary = 0
    private var accentBg = 0
    private var accentText = 0
    private var greenBg = 0
    private var greenText = 0
    private var amberBg = 0
    private var amberText = 0
    private var redBg = 0
    private var redText = 0
    private var neutralBg = 0
    private var neutralText = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Hide recent-apps thumbnails without blacking out live scrcpy mirroring;
        // the invitation short code input remains password-masked and cleared on submit.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        initPalette()
        window.decorView.setBackgroundColor(bgColor)

        val settings = getSharedPreferences("settings", MODE_PRIVATE)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgColor)
            setPadding(dp(20), dp(16), dp(20), dp(28))
        }

        root.addView(buildHeader())
        setupCard = buildSetupCard(settings)
        root.addView(setupCard, marginParams(top = 20))
        pairedSection = buildPairedSection(settings)
        root.addView(pairedSection, marginParams(top = 20))

        val scroll = ScrollView(this).apply {
            setBackgroundColor(bgColor)
            isFillViewport = true
            addView(root)
            fitsSystemWindows = true
        }
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(scroll)
        renderState(null)
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        refreshStatus()
    }

    override fun onPause() {
        resumed = false
        main.removeCallbacks(pollStatus)
        super.onPause()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun initPalette() {
        darkMode = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        if (darkMode) {
            bgColor = Color.parseColor("#0F1115")
            cardBg = Color.parseColor("#181B22")
            cardBorder = Color.parseColor("#272C36")
            inputBg = Color.parseColor("#11141A")
            textPrimary = Color.parseColor("#F3F4F6")
            textSecondary = Color.parseColor("#9CA3AF")
            accentBg = Color.parseColor("#F3F4F6")
            accentText = Color.parseColor("#0F1115")
            greenBg = Color.parseColor("#132A1E")
            greenText = Color.parseColor("#4ADE80")
            amberBg = Color.parseColor("#2C2211")
            amberText = Color.parseColor("#FBBF24")
            redBg = Color.parseColor("#2E1619")
            redText = Color.parseColor("#F87171")
            neutralBg = Color.parseColor("#232731")
            neutralText = Color.parseColor("#9CA3AF")
        } else {
            bgColor = Color.parseColor("#F5F6F8")
            cardBg = Color.parseColor("#FFFFFF")
            cardBorder = Color.parseColor("#E5E7EB")
            inputBg = Color.parseColor("#F9FAFB")
            textPrimary = Color.parseColor("#111827")
            textSecondary = Color.parseColor("#6B7280")
            accentBg = Color.parseColor("#111827")
            accentText = Color.parseColor("#FFFFFF")
            greenBg = Color.parseColor("#DCFCE7")
            greenText = Color.parseColor("#166534")
            amberBg = Color.parseColor("#FEF3C7")
            amberText = Color.parseColor("#92400E")
            redBg = Color.parseColor("#FEE2E2")
            redText = Color.parseColor("#991B1B")
            neutralBg = Color.parseColor("#E5E7EB")
            neutralText = Color.parseColor("#4B5563")
        }
    }

    private fun buildHeader(): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val icon = ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            scaleType = ImageView.ScaleType.FIT_CENTER
        }
        row.addView(icon, LinearLayout.LayoutParams(dp(44), dp(44)).apply { marginEnd = dp(12) })

        val titles = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        titles.addView(TextView(this).apply {
            text = "Styx"
            textSize = 22f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            setTextColor(textPrimary)
        })
        headerSubtitle = TextView(this).apply {
            text = "Android Host"
            textSize = 13f
            setTextColor(textSecondary)
        }
        titles.addView(headerSubtitle)
        row.addView(titles, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        statusPill = pill("Checking", neutralBg, neutralText)
        row.addView(statusPill)
        return row
    }

    private fun buildSetupCard(settings: android.content.SharedPreferences): LinearLayout {
        val card = cardContainer()
        card.addView(sectionTitle("Pair with Gateway"))
        card.addView(TextView(this).apply {
            text = "Enter your Gateway address and one-time invitation short code."
            textSize = 14f
            setTextColor(textSecondary)
            setPadding(0, dp(4), 0, dp(16))
        })

        gatewayInput = styledInput("https://your-gateway:port", settings.getString("gateway_url", "") ?: "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        codeInput = styledInput("Invitation short code", "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        labelInput = styledInput("Device name", settings.getString("device_label", Build.MODEL) ?: Build.MODEL, InputType.TYPE_CLASS_TEXT)

        card.addView(fieldLabel("Gateway URL"))
        card.addView(gatewayInput, marginParams(top = 6, bottom = 14))
        card.addView(fieldLabel("Invitation code"))
        card.addView(codeInput, marginParams(top = 6, bottom = 14))
        card.addView(fieldLabel("Device name"))
        card.addView(labelInput, marginParams(top = 6, bottom = 18))

        pairButton = primaryButton("Pair Phone") { onPairClicked(settings) }
        card.addView(pairButton, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(48)))

        setupMessage = TextView(this).apply {
            textSize = 13f
            setTextColor(redText)
            visibility = View.GONE
            setPadding(0, dp(12), 0, 0)
        }
        card.addView(setupMessage)
        return card
    }

    private fun buildPairedSection(settings: android.content.SharedPreferences): LinearLayout {
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        // 1. Host Connection Card
        val hostCard = cardContainer()
        hostCard.addView(sectionTitle("Connection"))
        val deviceRow = infoRow("Device", settings.getString("device_label", Build.MODEL) ?: Build.MODEL)
        deviceValue = deviceRow.second
        hostCard.addView(deviceRow.first, marginParams(top = 12))

        val gwRow = infoRow("Gateway", settings.getString("gateway_url", "").orEmpty().ifBlank { "Configured" })
        gatewayValue = gwRow.second
        hostCard.addView(gwRow.first, marginParams(top = 10))

        val envRow = infoRow("Environment", "", monospace = true)
        envIdRow = envRow.first
        envIdValue = envRow.second
        envIdRow.visibility = View.GONE
        hostCard.addView(envIdRow, marginParams(top = 10))

        issueBanner = TextView(this).apply {
            textSize = 13f
            setTextColor(amberText)
            background = roundedRect(amberBg, 0, dp(10))
            setPadding(dp(12), dp(10), dp(12), dp(10))
            visibility = View.GONE
        }
        hostCard.addView(issueBanner, marginParams(top = 14))

        toggleHostButton = primaryButton("Start Host") {
            if (hostActive) {
                stopHost()
                refreshStatus()
            } else {
                startHost()
            }
        }
        hostCard.addView(toggleHostButton, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(48)).apply {
            topMargin = dp(18)
        })
        container.addView(hostCard)

        // 2. Permissions Card
        val permCard = cardContainer()
        permCard.addView(sectionTitle("Permissions"))
        permCard.addView(TextView(this).apply {
            text = "Required for screen observation, touch input and reliable background connections."
            textSize = 13f
            setTextColor(textSecondary)
            setPadding(0, dp(4), 0, dp(14))
        })

        val accRow = permissionRow("Android Control", "Enable") {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
        accessibilityBadge = accRow.second
        accessibilityAction = accRow.third
        permCard.addView(accRow.first)

        permCard.addView(divider(), LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1)).apply {
            topMargin = dp(12)
            bottomMargin = dp(12)
        })

        val batRow = permissionRow("Background Activity", "Allow") {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
        batteryBadge = batRow.second
        batteryAction = batRow.third
        permCard.addView(batRow.first)
        container.addView(permCard, marginParams(top = 14))

        // 3. Footer Forget Action
        forgetButton = Button(this).apply {
            text = "Forget Pairing"
            isAllCaps = false
            textSize = 14f
            setTextColor(redText)
            background = roundedRect(Color.TRANSPARENT, 0, dp(10))
            stateListAnimator = null
            setOnClickListener { confirmForgetPairing() }
        }
        container.addView(forgetButton, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(44)).apply {
            topMargin = dp(16)
        })
        return container
    }

    private fun onPairClicked(settings: android.content.SharedPreferences) {
        val gatewayUrl = gatewayInput.text.toString().trim()
        val invitationCode = codeInput.text.toString().trim()
        val deviceLabel = labelInput.text.toString().trim().ifEmpty { Build.MODEL }
        if (gatewayUrl.isBlank() || invitationCode.isBlank()) {
            setupMessage.text = "Enter your Gateway URL and invitation short code."
            setupMessage.setTextColor(redText)
            setupMessage.visibility = View.VISIBLE
            return
        }
        codeInput.text.clear()
        busy = true
        pairButton.isEnabled = false
        pairButton.text = "Pairing…"
        setupMessage.visibility = View.GONE
        settings.edit().putString("gateway_url", gatewayUrl).putString("device_label", deviceLabel).apply()
        worker.execute {
            try {
                val result = JSONObject(NativeHost.pair(gatewayUrl, invitationCode, deviceLabel, AndroidPlatform(applicationContext)))
                runOnUiThread {
                    busy = false
                    pairButton.isEnabled = true
                    pairButton.text = "Pair Phone"
                    if (result.optBoolean("ok", false)) {
                        deviceValue.text = deviceLabel
                        gatewayValue.text = gatewayUrl
                        startHost()
                    } else {
                        val code = result.optJSONObject("error")?.optString("code")?.takeIf { it.isNotBlank() }
                        setupMessage.text = if (code != null) "Pairing failed ($code)." else "Pairing failed. Check the Gateway address and invitation code."
                        setupMessage.setTextColor(redText)
                        setupMessage.visibility = View.VISIBLE
                    }
                    refreshStatus()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    busy = false
                    pairButton.isEnabled = true
                    pairButton.text = "Pair Phone"
                    setupMessage.text = "Pairing failed. Check the Gateway address and invitation state."
                    setupMessage.setTextColor(redText)
                    setupMessage.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun confirmForgetPairing() {
        AlertDialog.Builder(this)
            .setTitle("Forget pairing?")
            .setMessage("Stop this Host and remove its local pairing. A new invitation is required to pair again. Revoke the old device separately on your Gateway.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Forget") { _, _ ->
                stopHost()
                busy = true
                forgetButton.isEnabled = false
                toggleHostButton.isEnabled = false
                worker.execute {
                    runCatching { NativeHost.forget(AndroidPlatform(applicationContext)) }
                    runOnUiThread {
                        busy = false
                        codeInput.text.clear()
                        forgetButton.isEnabled = true
                        toggleHostButton.isEnabled = true
                        setupMessage.visibility = View.GONE
                        refreshStatus()
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
            val paired = CredentialStore(applicationContext).exists()
            val state = runCatching { JSONObject(NativeHost.status()) }.getOrDefault(JSONObject())
                .put("paired", paired)
                .put("permissions", AndroidPlatform.readiness(applicationContext))
            runOnUiThread {
                renderState(state)
                statusPending = false
                if (resumed) main.postDelayed(pollStatus, 1000)
            }
        }
    }

    private fun renderState(state: JSONObject?) {
        val paired = state?.optBoolean("paired", false) ?: CredentialStore(applicationContext).exists()
        val rawState = state?.optString("state").orEmpty()
        val envId = state?.optString("environment_id").orEmpty()
        val errCode = state?.optString("code")?.takeIf { it.isNotBlank() && it != "null" }
        val perms = state?.optJSONObject("permissions")
        val accReady = perms?.optBoolean("accessibility", false) ?: false
        val batReady = perms?.optBoolean("ignoring_battery_optimizations", false) ?: false

        val settings = getSharedPreferences("settings", MODE_PRIVATE)
        val savedGateway = settings.getString("gateway_url", "").orEmpty()
        val savedLabel = settings.getString("device_label", Build.MODEL).orEmpty().ifBlank { Build.MODEL }
        deviceValue.text = savedLabel
        gatewayValue.text = savedGateway.ifBlank { "Configured" }

        setupCard.visibility = if (paired) View.GONE else View.VISIBLE
        pairedSection.visibility = if (paired) View.VISIBLE else View.GONE

        hostActive = paired && rawState in setOf("connected", "starting", "running", "connecting", "reconnecting")

        // Header status pill
        when {
            !paired -> applyPill(statusPill, "Not Paired", neutralBg, neutralText)
            rawState == "connected" -> applyPill(statusPill, "Connected", greenBg, greenText)
            rawState in setOf("starting", "running", "connecting", "reconnecting") -> applyPill(statusPill, "Connecting", amberBg, amberText)
            rawState in setOf("revoked", "failed") -> applyPill(statusPill, "Attention", redBg, redText)
            else -> applyPill(statusPill, "Stopped", neutralBg, neutralText)
        }
        headerSubtitle.text = if (paired) savedLabel else "Android Host"

        if (envId.isNotBlank()) {
            envIdValue.text = envId
            envIdRow.visibility = View.VISIBLE
        } else {
            envIdRow.visibility = View.GONE
        }

        if (errCode != null && paired) {
            issueBanner.text = "Status notice: $errCode"
            issueBanner.visibility = View.VISIBLE
        } else {
            issueBanner.visibility = View.GONE
        }

        // Toggle Host primary/secondary styling
        if (hostActive) {
            toggleHostButton.text = "Stop Host"
            toggleHostButton.setTextColor(textPrimary)
            toggleHostButton.background = roundedRect(Color.TRANSPARENT, cardBorder, dp(12))
        } else {
            toggleHostButton.text = "Start Host"
            toggleHostButton.setTextColor(accentText)
            toggleHostButton.background = roundedRect(accentBg, 0, dp(12))
        }
        toggleHostButton.isEnabled = !busy

        // Permissions checklist
        if (accReady) {
            applyPill(accessibilityBadge, "Enabled", greenBg, greenText)
            accessibilityBadge.visibility = View.VISIBLE
            accessibilityAction.visibility = View.GONE
        } else {
            accessibilityBadge.visibility = View.GONE
            accessibilityAction.visibility = View.VISIBLE
        }
        if (batReady) {
            applyPill(batteryBadge, "Unrestricted", greenBg, greenText)
            batteryBadge.visibility = View.VISIBLE
            batteryAction.visibility = View.GONE
        } else {
            batteryBadge.visibility = View.GONE
            batteryAction.visibility = View.VISIBLE
        }
    }

    // --- Compact UI builders (zero external dependencies) ---

    private fun cardContainer() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = roundedRect(cardBg, cardBorder, dp(16))
        setPadding(dp(18), dp(18), dp(18), dp(18))
    }

    private fun sectionTitle(title: String) = TextView(this).apply {
        text = title
        textSize = 16f
        typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        setTextColor(textPrimary)
    }

    private fun fieldLabel(label: String) = TextView(this).apply {
        text = label
        textSize = 12f
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        setTextColor(textSecondary)
    }

    private fun styledInput(hintText: String, value: String, type: Int) = EditText(this).apply {
        hint = hintText
        setHintTextColor(textSecondary)
        setTextColor(textPrimary)
        textSize = 15f
        inputType = type
        setSingleLine(true)
        setText(value)
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        background = roundedRect(inputBg, cardBorder, dp(10))
        setPadding(dp(14), dp(12), dp(14), dp(12))
    }

    private fun primaryButton(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 15f
        typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        setTextColor(accentText)
        background = roundedRect(accentBg, 0, dp(12))
        stateListAnimator = null
        setOnClickListener { action() }
    }

    private fun infoRow(label: String, value: String, monospace: Boolean = false): Pair<LinearLayout, TextView> {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val lbl = TextView(this).apply {
            text = label
            textSize = 14f
            setTextColor(textSecondary)
        }
        val valView = TextView(this).apply {
            text = value
            textSize = if (monospace) 12.5f else 14f
            typeface = if (monospace) Typeface.MONOSPACE else Typeface.DEFAULT
            setTextColor(textPrimary)
            gravity = Gravity.END
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.MIDDLE
            setTextIsSelectable(true)
        }
        row.addView(lbl, LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
            marginEnd = dp(12)
        })
        row.addView(valView, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        return row to valView
    }

    private fun permissionRow(title: String, actionLabel: String, onClick: () -> Unit): Triple<LinearLayout, TextView, Button> {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val lbl = TextView(this).apply {
            text = title
            textSize = 14f
            setTextColor(textPrimary)
        }
        row.addView(lbl, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        val badge = pill("Ready", greenBg, greenText)
        row.addView(badge)
        val btn = Button(this).apply {
            text = actionLabel
            isAllCaps = false
            textSize = 13f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            setTextColor(accentText)
            background = roundedRect(accentBg, 0, dp(18))
            stateListAnimator = null
            minHeight = 0
            minimumHeight = 0
            minWidth = 0
            minimumWidth = 0
            setPadding(dp(14), dp(6), dp(14), dp(6))
            setOnClickListener { onClick() }
        }
        row.addView(btn)
        return Triple(row, badge, btn)
    }

    private fun pill(text: String, bg: Int, fg: Int) = TextView(this).apply {
        this.text = text
        textSize = 12f
        typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        setTextColor(fg)
        background = roundedRect(bg, 0, dp(999))
        setPadding(dp(12), dp(5), dp(12), dp(5))
    }

    private fun applyPill(view: TextView, label: String, bg: Int, fg: Int) {
        view.text = label
        view.setTextColor(fg)
        view.background = roundedRect(bg, 0, dp(999))
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(cardBorder)
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun roundedRect(fill: Int, stroke: Int, radiusPx: Int) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = radiusPx.toFloat()
        setColor(fill)
        if (stroke != 0) setStroke(dp(1), stroke)
    }

    private fun marginParams(top: Int = 0, bottom: Int = 0) =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
            bottomMargin = dp(bottom)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
