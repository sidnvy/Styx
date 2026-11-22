package com.styx.host

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Android owns service lifetime; Rust owns the single authenticated Host connection. */
class HostService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    private val stopping = AtomicBoolean(false)
    private lateinit var platform: AndroidPlatform

    override fun onCreate() {
        super.onCreate()
        platform = AndroidPlatform(applicationContext)
        val channel = NotificationChannel(
            CHANNEL,
            "Styx Host connection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            setShowBadge(false)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            if (stopping.compareAndSet(false, true)) {
                StyxAccessibilityService.instance?.clearObservation()
                worker.execute {
                    NativeHost.stop()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            return START_NOT_STICKY
        }
        stopping.set(false)
        promoteForeground(notification("Connecting to your paired Gateway"))
        worker.execute {
            if (stopping.get()) return@execute
            val label = getSharedPreferences("settings", MODE_PRIVATE).getString("device_label", Build.MODEL)
            val config = JSONObject().put("files_dir", filesDir.absolutePath).put("device_label", label)
            val result = NativeHost.start(config.toString(), platform)
            if (stopping.get()) return@execute
            val response = JSONObject(result)
            val text = if (!response.optBoolean("ok", false)) {
                "Connection needs attention — open Styx"
            } else {
                "Host is running — open for connection status"
            }
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
        }
        return START_STICKY
    }

    override fun onDestroy() {
        if (stopping.compareAndSet(false, true)) {
            StyxAccessibilityService.instance?.clearObservation()
            worker.execute { NativeHost.stop() }
        }
        worker.shutdown()
        try {
            worker.awaitTermination(5, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun promoteForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notification(text: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, HostService::class.java).setAction(STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_styx)
            .setContentTitle("Styx Host")
            .setContentText(text)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
        if (Build.VERSION.SDK_INT >= 31) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return builder.build()
    }

    companion object {
        const val STOP = "com.styx.host.STOP"
        private const val CHANNEL = "styx-host"
        private const val NOTIFICATION_ID = 1
    }
}
