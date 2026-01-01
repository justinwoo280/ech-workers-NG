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

class EchVpnService : VpnService(), core.SocketProtector {

    companion object {
        const val TAG = "EchVpnService"
        const val ACTION_CONNECT = "com.echworkers.android.CONNECT"
        const val ACTION_DISCONNECT = "com.echworkers.android.DISCONNECT"
        const val ACTION_STATE_CHANGED = "com.echworkers.android.VPN_STATE_CHANGED"
        const val EXTRA_SERVER_ADDR = "server_addr"
        const val EXTRA_SERVER_IP = "server_ip"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_ENABLE_ECH = "enable_ech"
        const val EXTRA_ENABLE_YAMUX = "enable_yamux"
        const val EXTRA_ECH_DOMAIN = "ech_domain"
        const val EXTRA_ECH_DOH_SERVER = "ech_doh_server"
        const val EXTRA_PROXY_ADDR = "proxy_addr"
        const val EXTRA_STATE = "state"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "ech_vpn_channel"
        
        // 使用固定端口以便测试
        private const val FIXED_PROXY_PORT = 10808
        
        // 静态变量存储当前代理地址
        @Volatile
        private var currentProxyAddr: String? = null
        
        // 获取当前代理地址
        fun getProxyAddress(): String? = currentProxyAddr

        private const val VPN_MTU = 1500
        private const val PRIVATE_VLAN4_CLIENT = "10.0.0.2"
        private const val PRIVATE_VLAN4_ROUTER = "10.0.0.1"
        private const val PRIVATE_VLAN6_CLIENT = "fd00::2"
        private const val PRIVATE_VLAN6_ROUTER = "fd00::1"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var proxyJob: Job? = null
    private val serviceJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + serviceJob)

    private var localProxyAddr: String? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // 设置 socket 保护器，防止 VPN 流量循环
        Core.setSocketProtector(this)
    }

    // 实现 SocketProtector 接口 - 保护 socket 不经过 VPN
    override fun protect(fd: Long): Boolean {
        return try {
            val result = protect(fd.toInt())
            Log.d(TAG, "保护 socket fd=$fd 结果: $result")
            result
        } catch (e: Exception) {
            Log.e(TAG, "保护 socket 失败: fd=$fd", e)
            false
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                // 如果已经在连接中，先断开
                if (proxyJob?.isActive == true) {
                    Log.w(TAG, "已有连接正在运行，先断开旧连接")
                    disconnect()
                    // 等待断开完成后再连接
                    scope.launch {
                        delay(1000)
                        startConnection(intent)
                    }
                } else {
                    startConnection(intent)
                }
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
        }
        return START_STICKY
    }

    private fun startConnection(intent: Intent) {
        val serverAddr = intent.getStringExtra(EXTRA_SERVER_ADDR) ?: ""
        val serverIp = intent.getStringExtra(EXTRA_SERVER_IP) ?: ""
        val token = intent.getStringExtra(EXTRA_TOKEN) ?: ""
        val enableEch = intent.getBooleanExtra(EXTRA_ENABLE_ECH, true)
        val enableYamux = intent.getBooleanExtra(EXTRA_ENABLE_YAMUX, true)
        val echDomain = intent.getStringExtra(EXTRA_ECH_DOMAIN) ?: ""
        val echDohServer = intent.getStringExtra(EXTRA_ECH_DOH_SERVER) ?: ""

        connect(serverAddr, serverIp, token, enableEch, enableYamux, echDomain, echDohServer)
    }

    private fun connect(
        serverAddr: String,
        serverIp: String,
        token: String,
        enableEch: Boolean,
        enableYamux: Boolean,
        echDomain: String,
        echDohServer: String
    ) {
        Log.i(TAG, "正在连接: $serverAddr (ECH: $enableEch, Domain: $echDomain, DOH: $echDohServer)")

        startForeground(NOTIFICATION_ID, createNotification("正在连接..."))
        
        proxyJob = scope.launch {
            try {
                // 1. 建立 VPN 接口
                Log.i(TAG, "[1/3] 建立 VPN 接口")
                establishVpn()
                Log.i(TAG, "VPN 接口已建立")

                // 2. 启动 SOCKS5 代理服务器
                Log.i(TAG, "[2/3] 启动 SOCKS5 代理")
                localProxyAddr = Core.startProxy(
                    serverAddr,
                    serverIp,
                    token,
                    "127.0.0.1:$FIXED_PROXY_PORT",  // 使用固定端口
                    enableEch,
                    enableYamux,
                    echDomain,
                    echDohServer
                )
                currentProxyAddr = localProxyAddr  // 保存到静态变量
                Log.i(TAG, "SOCKS5 代理已启动: $localProxyAddr")

                // 3. 启动 TUN2SOCKS (在独立协程中运行，不阻塞)
                Log.i(TAG, "[3/3] 启动 TUN2SOCKS")
                launch {
                    startTun2Socks()
                }
                
                // 等待 TUN 启动
                delay(1000)  // 增加等待时间确保 TUN 完全启动
                
                if (Core.isTunRunning()) {
                    Log.i(TAG, "TUN2SOCKS 已启动")
                    updateNotification("已连接")
                    Log.i(TAG, "连接成功，代理地址: $localProxyAddr")
                    
                    // 广播连接成功和代理地址
                    sendBroadcast(Intent(ACTION_STATE_CHANGED).apply {
                        putExtra(EXTRA_STATE, "connected")
                        putExtra(EXTRA_PROXY_ADDR, localProxyAddr)
                    })
                } else {
                    throw Exception("TUN2SOCKS 启动失败")
                }

            } catch (e: Exception) {
                Log.e(TAG, "连接失败", e)
                e.printStackTrace()
                updateNotification("连接失败: ${e.message}")
                disconnect()
            }
        }
    }

    private fun establishVpn() {
        // 加载 DNS 配置
        val configService = com.echworkers.android.service.ConfigService(this)
        val config = configService.load()
        val fallbackDns = config.dnsConfig.fallbackDns.ifEmpty { "1.1.1.1" }

        val builder = Builder()
            .setSession("ECH Workers VPN")
            .setMtu(VPN_MTU)
            .addAddress(PRIVATE_VLAN4_CLIENT, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(fallbackDns)  // 使用配置的 DNS

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
        val fd = vpnInterface?.fd ?: run {
            Log.e(TAG, "VPN 接口 fd 为空")
            return
        }
        val proxyAddr = localProxyAddr ?: run {
            Log.e(TAG, "代理地址为空")
            return
        }

        withContext(Dispatchers.IO) {
            try {
                Log.i(TAG, "启动 TUN2SOCKS: fd=$fd, proxy=$proxyAddr, mtu=$VPN_MTU")
                
                // 使用 Go 核心库的 TUN 处理 (gomobile 将 Go int 映射为 Java long)
                Core.startTun(fd.toLong(), proxyAddr, VPN_MTU.toLong())
                
                Log.i(TAG, "TUN2SOCKS 已启动，代理地址: $proxyAddr")
                
                // 验证 TUN 是否真的在运行
                delay(500)
                if (Core.isTunRunning()) {
                    Log.i(TAG, "TUN2SOCKS 运行状态确认: 正在运行")
                } else {
                    Log.e(TAG, "TUN2SOCKS 运行状态确认: 未运行")
                }

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

        // 取消连接协程
        proxyJob?.cancel()
        proxyJob = null

        // 停止 TUN 引擎
        try {
            if (Core.isTunRunning()) {
                Core.stopTun()
                Log.i(TAG, "TUN 已停止")
            }
        } catch (e: Exception) {
            Log.w(TAG, "停止 TUN 失败", e)
        }

        // 停止 SOCKS5 代理服务器
        try {
            if (Core.isProxyRunning()) {
                Core.stopProxy()
                Log.i(TAG, "SOCKS5 代理已停止")
            }
        } catch (e: Exception) {
            Log.w(TAG, "停止代理失败", e)
        }

        // 关闭 VPN 接口
        try {
            vpnInterface?.close()
            vpnInterface = null
            Log.i(TAG, "VPN 接口已关闭")
        } catch (e: Exception) {
            Log.w(TAG, "关闭 VPN 接口失败", e)
        }

        localProxyAddr = null
        currentProxyAddr = null  // 清除静态变量

        // 广播断开连接
        sendBroadcast(Intent(ACTION_STATE_CHANGED).apply {
            putExtra(EXTRA_STATE, "disconnected")
        })

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceJob.cancel()  // 取消所有子协程
        disconnect()
    }

    // OOM 防护：响应系统内存警告
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        when (level) {
            TRIM_MEMORY_RUNNING_LOW,
            TRIM_MEMORY_RUNNING_CRITICAL -> {
                Log.w(TAG, "系统内存不足，启用低内存模式 (level=$level)")
                Core.setLowMemoryMode(true)
            }
            TRIM_MEMORY_UI_HIDDEN -> {
                Log.i(TAG, "应用进入后台，优化内存使用")
            }
            TRIM_MEMORY_MODERATE,
            TRIM_MEMORY_COMPLETE -> {
                Log.w(TAG, "严重内存不足，限制连接 (level=$level)")
                Core.setLowMemoryMode(true)
            }
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        Log.e(TAG, "系统内存严重不足！启用紧急低内存模式")
        Core.setLowMemoryMode(true)
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
