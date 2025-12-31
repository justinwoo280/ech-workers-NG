package com.echworkers.android.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.echworkers.android.model.AppConfig
import com.echworkers.android.model.NodeConfig
import com.echworkers.android.service.ConfigService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val configService = ConfigService(application)

    private val _nodes = MutableLiveData<List<NodeConfig>>()
    val nodes: LiveData<List<NodeConfig>> = _nodes

    private val _selectedNode = MutableLiveData<NodeConfig?>()
    val selectedNode: LiveData<NodeConfig?> = _selectedNode

    private val _isConnected = MutableLiveData(false)
    val isConnected: LiveData<Boolean> = _isConnected

    private val _statusText = MutableLiveData("未连接")
    val statusText: LiveData<String> = _statusText

    // 连接测试结果
    private val _latency = MutableLiveData<Long?>()
    val latency: LiveData<Long?> = _latency

    private val _errorMessage = MutableLiveData<String?>()
    val errorMessage: LiveData<String?> = _errorMessage

    private val _isTesting = MutableLiveData(false)
    val isTesting: LiveData<Boolean> = _isTesting

    private var config: AppConfig

    init {
        config = configService.load()
        _nodes.value = config.nodes.toList()
        _selectedNode.value = config.nodes.find { it.id == config.selectedNodeId }
    }

    fun addNode(node: NodeConfig) {
        config.nodes.add(node)
        _nodes.value = config.nodes.toList()
        if (_selectedNode.value == null) {
            selectNode(node)
        }
        saveConfig()
    }

    fun updateNode(node: NodeConfig) {
        val index = config.nodes.indexOfFirst { it.id == node.id }
        if (index >= 0) {
            config.nodes[index] = node
            _nodes.value = config.nodes.toList()
            if (_selectedNode.value?.id == node.id) {
                _selectedNode.value = node
            }
            saveConfig()
        }
    }

    fun deleteNode(node: NodeConfig) {
        config.nodes.removeIf { it.id == node.id }
        _nodes.value = config.nodes.toList()
        if (_selectedNode.value?.id == node.id) {
            _selectedNode.value = config.nodes.firstOrNull()
            config.selectedNodeId = _selectedNode.value?.id
        }
        saveConfig()
    }

    fun selectNode(node: NodeConfig) {
        _selectedNode.value = node
        config.selectedNodeId = node.id
        saveConfig()
    }

    fun setConnected(connected: Boolean) {
        _isConnected.value = connected
        _statusText.value = if (connected) "已连接" else "未连接"
        if (!connected) {
            _latency.value = null
            _errorMessage.value = null
        }
    }

    // 测试连接（连接后自动调用）
    fun testConnection(proxyAddr: String) {
        if (_isTesting.value == true) return

        _isTesting.value = true
        _errorMessage.value = null

        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    core.Core.testProxy(proxyAddr, "https://cloudflare.com")
                } catch (e: Exception) {
                    null
                }
            }

            _isTesting.value = false

            if (result == null) {
                _latency.value = null
                _errorMessage.value = "测试失败"
            } else if (result.success) {
                _latency.value = result.latency
                _errorMessage.value = null
                _statusText.value = "已连接 · ${result.latency}ms"
            } else {
                _latency.value = null
                _errorMessage.value = if (result.error.isNullOrEmpty()) "HTTP ${result.httpCode}" else result.error
                _statusText.value = "连接失败"
            }
        }
    }

    fun clearTestResult() {
        _latency.value = null
        _errorMessage.value = null
    }

    fun saveConfig() {
        configService.save(config)
    }
}
