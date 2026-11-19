package com.styx.host.test

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** Installed only in the test APK. Contains no user data or product control surface. */
class FixtureActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.getBooleanExtra("finish_fixture", false)) { finish(); return }
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
        val pad = (32 * resources.displayMetrics.density).toInt()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            setBackgroundColor(BACKGROUND)
        }
        var clicks = 0
        val counter = TextView(this).apply { id = android.R.id.text1; text = "Clicks: 0"; textSize = 22f }
        val edit = EditText(this).apply { id = android.R.id.edit; setText("seed"); setSingleLine(true) }
        val increment = Button(this).apply {
            id = android.R.id.button1; text = "Increment fixture counter"
            setOnClickListener { clicks++; counter.text = "Clicks: $clicks" }
        }
        val secureState = TextView(this).apply { id = android.R.id.text2; text = "Secure: off" }
        val secure = Button(this).apply {
            id = android.R.id.button2; text = "Protect fixture screenshot"
            setOnClickListener { window.addFlags(WindowManager.LayoutParams.FLAG_SECURE); secureState.text = "Secure: on" }
        }
        layout.addView(TextView(this).apply { text = "STYX TEST CONTENT ONLY"; textSize = 22f })
        layout.addView(counter); layout.addView(edit); layout.addView(increment)
        layout.addView(secure); layout.addView(secureState)
        layout.isFocusableInTouchMode = true
        setContentView(layout)
        layout.requestFocus()
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra("finish_fixture", false)) finish()
    }
    companion object { val BACKGROUND: Int = Color.rgb(55, 114, 199) }
}
