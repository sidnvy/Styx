package com.styx.host.test;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** Real Activity transition used to test post-click Android observations. */
public class FixtureNextActivity extends Activity {
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView title = new TextView(this);
        title.setId(android.R.id.text1);
        title.setText("STYX NEXT TEST SCREEN");
        title.setTextSize(24f);
        setContentView(title);
    }
}
