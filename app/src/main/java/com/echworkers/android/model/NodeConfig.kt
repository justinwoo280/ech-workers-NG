package com.echworkers.android.model

import java.util.UUID

data class NodeConfig(
    val id: String = UUID.randomUUID().toString(),
    var name: String = "新节点",
    var serverAddr: String = "",
    var serverIp: String = "",
    var token: String = "",
    var enableEch: Boolean = true,
    var enableYamux: Boolean = true,
    var echDomain: String = "cloudflare-ech.com",
    var dnsServer: String = "1.1.1.1:53"
)

data class AppConfig(
    var nodes: MutableList<NodeConfig> = mutableListOf(),
    var selectedNodeId: String? = null,
    var perAppProxyEnabled: Boolean = false,
    var perAppProxyMode: String = "whitelist", // whitelist or blacklist
    var perAppProxyApps: MutableList<String> = mutableListOf()
)
