package com.styx.host

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import org.json.JSONObject
import java.util.concurrent.Executors

/** Android owns service lifetime; Rust owns the single authenticated Host connection. */
class HostService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var platform: AndroidPlatform

    override fun onCreate() {
        super.onCreate()
        platform = AndroidPlatform(applicationContext)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Styx Host connection", NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            StyxAccessibilityService.instance?.clearObservation()
            worker.execute {
                NativeHost.stop()
                stopSelf()
            }
            return START_NOT_STICKY
        }
        startForeground(1, notification("Connecting to your paired Gateway"))
        worker.execute {
            val label = getSharedPreferences("settings", MODE_PRIVATE).getString("device_label", Build.MODEL)
            val config = JSONObject().put("files_dir", filesDir.absolutePath).put("device_label", label)
            val result = NativeHost.start(config.toString(), platform)
            val response = JSONObject(result)
            if (!response.optBoolean("ok", false)) {
                getSystemService(NotificationManager::class.java).notify(1, notification("Connection needs attention — open Styx"))
            } else {
                getSystemService(NotificationManager::class.java).notify(1, notification("Host is running — open for connection status"))
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        StyxAccessibilityService.instance?.clearObservation()
        worker.execute { NativeHost.stop() }
        worker.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, HostService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Styx Host")
            .setContentText(text)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }

    companion object {
        const val STOP = "com.styx.host.STOP"
        private const val CHANNEL = "styx-host"
    }
}
