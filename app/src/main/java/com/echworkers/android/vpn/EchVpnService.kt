package com.echworkers.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.echworkers.android.MainActivity
import com.echworkers.android.R
import core.Core
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream

class EchVpnService : VpnService() {

    companion object {
        const val TAG = "EchVpnService"
        const val ACTION_CONNECT = "com.echworkers.android.CONNECT"
        const val ACTION_DISCONNECT = "com.echworkers.android.DISCONNECT"
        const val EXTRA_SERVER_ADDR = "server_addr"
        const val EXTRA_SERVER_IP = "server_ip"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_ENABLE_ECH = "enable_ech"
        const val EXTRA_ENABLE_YAMUX = "enable_yamux"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "ech_vpn_channel"

        private const val VPN_MTU = 1500
        private const val PRIVATE_VLAN4_CLIENT = "10.0.0.2"
        private const val PRIVATE_VLAN4_ROUTER = "10.0.0.1"
        private const val PRIVATE_VLAN6_CLIENT = "fd00::2"
        private const val PRIVATE_VLAN6_ROUTER = "fd00::1"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var localProxyAddr: String? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val serverAddr = intent.getStringExtra(EXTRA_SERVER_ADDR) ?: ""
                val serverIp = intent.getStringExtra(EXTRA_SERVER_IP) ?: ""
                val token = intent.getStringExtra(EXTRA_TOKEN) ?: ""
                val enableEch = intent.getBooleanExtra(EXTRA_ENABLE_ECH, true)
                val enableYamux = intent.getBooleanExtra(EXTRA_ENABLE_YAMUX, true)

                connect(serverAddr, serverIp, token, enableEch, enableYamux)
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
        }
        return START_STICKY
    }

    private fun connect(
        serverAddr: String,
        serverIp: String,
        token: String,
        enableEch: Boolean,
        enableYamux: Boolean
    ) {
        Log.i(TAG, "正在连接: $serverAddr")

        startForeground(NOTIFICATION_ID, createNotification("正在连接..."))

        proxyJob = scope.launch {
            try {
                // 启动本地 SOCKS5 代理
                val localAddr = "127.0.0.1:10808"
                localProxyAddr = Core.startProxy(
                    serverAddr,
                    serverIp,
                    token,
                    localAddr,
                    enableEch,
                    enableYamux
                )

                Log.i(TAG, "本地代理已启动: $localProxyAddr")

                // 建立 VPN 接口
                withContext(Dispatchers.Main) {
                    establishVpn()
                }

                updateNotification("已连接")
                Log.i(TAG, "VPN 已连接")

                // 启动 TUN -> SOCKS5 转发
                startTun2Socks()

            } catch (e: Exception) {
                Log.e(TAG, "连接失败", e)
                updateNotification("连接失败: ${e.message}")
                disconnect()
            }
        }
    }

    private fun establishVpn() {
        val builder = Builder()
            .setSession("ECH Workers VPN")
            .setMtu(VPN_MTU)
            .addAddress(PRIVATE_VLAN4_CLIENT, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")

        // IPv6 支持
        try {
            builder.addAddress(PRIVATE_VLAN6_CLIENT, 126)
            builder.addRoute("::", 0)
        } catch (e: Exception) {
            Log.w(TAG, "IPv6 配置失败", e)
        }

        // 排除本地代理地址
        builder.addDisallowedApplication(packageName)

        // 加载分应用代理配置
        loadPerAppProxyConfig(builder)

        vpnInterface = builder.establish()

        if (vpnInterface == null) {
            throw Exception("无法建立 VPN 接口")
        }
    }

    private fun loadPerAppProxyConfig(builder: Builder) {
        try {
            val configService = com.echworkers.android.service.ConfigService(this)
            val config = configService.load()

            if (config.perAppProxyEnabled && config.perAppProxyApps.isNotEmpty()) {
                when (config.perAppProxyMode) {
                    "whitelist" -> {
                        // 白名单模式：只有列表中的应用走代理
                        Log.i(TAG, "分应用代理：白名单模式，${config.perAppProxyApps.size} 个应用")
                        config.perAppProxyApps.forEach { packageName ->
                            try {
                                builder.addAllowedApplication(packageName)
                            } catch (e: Exception) {
                                Log.w(TAG, "添加白名单应用失败: $packageName", e)
                            }
                        }
                    }
                    "blacklist" -> {
                        // 黑名单模式：列表中的应用不走代理
                        Log.i(TAG, "分应用代理：黑名单模式，${config.perAppProxyApps.size} 个应用")
                        config.perAppProxyApps.forEach { packageName ->
                            try {
                                builder.addDisallowedApplication(packageName)
                            } catch (e: Exception) {
                                Log.w(TAG, "添加黑名单应用失败: $packageName", e)
                            }
                        }
                    }
                }
            } else {
                Log.i(TAG, "分应用代理：全局模式")
            }
        } catch (e: Exception) {
            Log.e(TAG, "加载分应用代理配置失败", e)
        }
    }

    private suspend fun startTun2Socks() {
        val fd = vpnInterface?.fd ?: return
        val proxyAddr = localProxyAddr ?: return

        withContext(Dispatchers.IO) {
            try {
                // 使用 Go 核心库的 TUN 处理
                Core.startTun(fd.toLong(), proxyAddr, VPN_MTU.toLong())
                Log.i(TAG, "TUN2SOCKS 已启动，代理地址: $proxyAddr")

                // 保持运行直到停止
                while (isActive && vpnInterface != null && Core.isTunRunning()) {
                    delay(1000)
                }
            } catch (e: Exception) {
                Log.e(TAG, "TUN2SOCKS 启动失败", e)
                throw e
            }
        }
    }

    private fun disconnect() {
        Log.i(TAG, "正在断开连接")

        proxyJob?.cancel()
        proxyJob = null

        // 停止 TUN 引擎
        try {
            Core.stopTun()
        } catch (e: Exception) {
            Log.w(TAG, "停止 TUN 失败", e)
        }

        vpnInterface?.close()
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        disconnect()
        scope.cancel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN 服务",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "ECH Workers VPN 服务通知"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ECH Workers")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, createNotification(status))
    }
}
