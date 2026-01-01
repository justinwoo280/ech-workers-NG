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
    // ECH 连接配置 (仅当 enableEch=true 时生效)
    var echDomain: String = "cloudflare-ech.com",          // ECH 查询域名
    var echDohServer: String = "dns.alidns.com/dns-query"  // ECH 用的 DOH 服务器 (无需 https://)
)

data class DnsConfig(
    var dohServer: String = "cloudflare-dns.com/dns-query",  // DOH 服务器 (无需 https://)
    var dotServer: String = "",                                        // DOT 服务器 (可选)
    var fallbackDns: String = "1.1.1.1"                               // 回退 DNS
)

data class AppConfig(
    var nodes: MutableList<NodeConfig> = mutableListOf(),
    var selectedNodeId: String? = null,
    var dnsConfig: DnsConfig = DnsConfig(),
    var perAppProxyEnabled: Boolean = false,
    var perAppProxyMode: String = "whitelist", // whitelist or blacklist
    var perAppProxyApps: MutableList<String> = mutableListOf()
)
