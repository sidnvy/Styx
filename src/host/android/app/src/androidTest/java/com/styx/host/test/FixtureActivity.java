package com.styx.host.test;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Standalone test APK Activity: plain Android/Java, without the target APK's Kotlin runtime. */
public class FixtureActivity extends Activity {
    public static final int BACKGROUND = Color.rgb(55, 114, 199);
    private int clicks;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getIntent().getBooleanExtra("finish_fixture", false)) { finish(); return; }
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        int pad = (int) (32 * getResources().getDisplayMetrics().density);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(pad, pad * 2, pad, pad);
        layout.setBackgroundColor(BACKGROUND);
        TextView title = new TextView(this);
        title.setText("STYX TEST CONTENT ONLY"); title.setTextSize(22f);
        TextView counter = new TextView(this);
        counter.setId(android.R.id.text1); counter.setText("Clicks: 0"); counter.setTextSize(22f);
        EditText edit = new EditText(this);
        edit.setId(android.R.id.edit); edit.setText("seed"); edit.setSingleLine(true);
        Button increment = incrementButton(counter);
        TextView secureState = new TextView(this);
        secureState.setId(android.R.id.text2); secureState.setText("Secure: off");
        Button secure = new Button(this);
        secure.setId(android.R.id.button2); secure.setText("Protect fixture screenshot");
        secure.setOnClickListener(view -> {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            secureState.setText("Secure: on");
        });
        layout.addView(title); layout.addView(counter); layout.addView(edit); layout.addView(increment);
        layout.addView(secure); layout.addView(secureState);
        Button transition = new Button(this);
        transition.setId(android.R.id.button3);
        transition.setText("Open next test screen");
        transition.setOnClickListener(view ->
            startActivity(new Intent(this, FixtureNextActivity.class)));
        layout.addView(transition);
        layout.setFocusableInTouchMode(true);
        setContentView(layout);
        layout.requestFocus();
    }

    private Button incrementButton(TextView counter) {
        Button button = new Button(this);
        button.setId(android.R.id.button1); button.setText("Increment fixture counter");
        button.setOnClickListener(view -> counter.setText("Clicks: " + ++clicks));
        return button;
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent.getBooleanExtra("finish_fixture", false)) { finish(); return; }
        if (intent.getBooleanExtra("replace_increment", false)) {
            Button previous = findViewById(android.R.id.button1);
            LinearLayout parent = (LinearLayout) previous.getParent();
            int index = parent.indexOfChild(previous);
            android.view.ViewGroup.LayoutParams params = previous.getLayoutParams();
            parent.removeView(previous);
            parent.addView(incrementButton(findViewById(android.R.id.text1)), index, params);
        }
    }
}
