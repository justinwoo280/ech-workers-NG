package com.echworkers.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import com.echworkers.android.databinding.ActivityMainBinding
import com.echworkers.android.model.NodeConfig
import com.echworkers.android.ui.NodeAdapter
import com.echworkers.android.ui.NodeEditDialog
import com.echworkers.android.viewmodel.MainViewModel
import com.echworkers.android.vpn.EchVpnService

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: MainViewModel
    private lateinit var nodeAdapter: NodeAdapter

    private var localProxyAddr: String? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, "需要 VPN 权限才能运行", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        viewModel = ViewModelProvider(this)[MainViewModel::class.java]

        setupUI()
        observeViewModel()
    }

    private fun setupUI() {
        // 节点列表
        nodeAdapter = NodeAdapter(
            onItemClick = { node ->
                viewModel.selectNode(node)
            },
            onItemLongClick = { node ->
                showNodeEditDialog(node)
            }
        )
        binding.recyclerNodes.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = nodeAdapter
        }

        // 添加节点按钮
        binding.fabAddNode.setOnClickListener {
            showNodeEditDialog(null)
        }

        // 连接按钮
        binding.btnConnect.setOnClickListener {
            if (viewModel.isConnected.value == true) {
                stopVpn()
            } else {
                requestVpnPermission()
            }
        }

        // 分应用代理设置
        binding.btnAppProxy.setOnClickListener {
            startActivity(Intent(this, AppProxyActivity::class.java))
        }
    }

    private fun observeViewModel() {
        viewModel.nodes.observe(this) { nodes ->
            nodeAdapter.submitList(nodes)
        }

        viewModel.selectedNode.observe(this) { node ->
            nodeAdapter.setSelectedNode(node)
            binding.tvSelectedNode.text = node?.name ?: "未选择节点"
        }

        viewModel.isConnected.observe(this) { connected ->
            updateConnectionUI(connected)
        }

        viewModel.statusText.observe(this) { status ->
            binding.tvStatus.text = status
        }

        // 延迟显示
        viewModel.latency.observe(this) { latency ->
            if (latency != null) {
                binding.tvLatency.text = latency.toString()
                binding.ivStatusIcon.setImageResource(R.drawable.ic_connected)
            } else {
                binding.tvLatency.text = "--"
            }
        }

        // 错误信息
        viewModel.errorMessage.observe(this) { error ->
            if (error != null) {
                binding.tvError.text = error
                binding.tvError.visibility = View.VISIBLE
                binding.ivStatusIcon.setImageResource(R.drawable.ic_error)
            } else {
                binding.tvError.visibility = View.GONE
            }
        }

        // 测试中状态
        viewModel.isTesting.observe(this) { testing ->
            if (testing) {
                binding.tvLatency.text = "..."
            }
        }
    }

    private fun updateConnectionUI(connected: Boolean) {
        if (connected) {
            binding.btnConnect.text = "断开连接"
            binding.btnConnect.setBackgroundColor(getColor(R.color.disconnect_button))
        } else {
            binding.btnConnect.text = "连接"
            binding.btnConnect.setBackgroundColor(getColor(R.color.connect_button))
            binding.ivStatusIcon.setImageResource(R.drawable.ic_disconnected)
            binding.tvLatency.text = "--"
            binding.tvError.visibility = View.GONE
        }
        binding.fabAddNode.isEnabled = !connected
        binding.btnAppProxy.isEnabled = !connected
    }

    private fun showNodeEditDialog(node: NodeConfig?) {
        NodeEditDialog(this, node) { editedNode ->
            if (node == null) {
                viewModel.addNode(editedNode)
            } else {
                viewModel.updateNode(editedNode)
            }
        }.show()
    }

    private fun requestVpnPermission() {
        val selectedNode = viewModel.selectedNode.value
        if (selectedNode == null) {
            Toast.makeText(this, "请先选择节点", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val node = viewModel.selectedNode.value ?: return

        val intent = Intent(this, EchVpnService::class.java).apply {
            action = EchVpnService.ACTION_CONNECT
            putExtra(EchVpnService.EXTRA_SERVER_ADDR, node.serverAddr)
            putExtra(EchVpnService.EXTRA_SERVER_IP, node.serverIp)
            putExtra(EchVpnService.EXTRA_TOKEN, node.token)
            putExtra(EchVpnService.EXTRA_ENABLE_ECH, node.enableEch)
            putExtra(EchVpnService.EXTRA_ENABLE_YAMUX, node.enableYamux)
            // ECH 连接配置 (节点级别)
            putExtra(EchVpnService.EXTRA_ECH_DOMAIN, node.echDomain)
            putExtra(EchVpnService.EXTRA_ECH_DOH_SERVER, node.echDohServer)
        }
        startService(intent)
        viewModel.setConnected(true)

        // 连接后自动测试
        localProxyAddr = "127.0.0.1:10808"
        viewModel.testConnection(localProxyAddr!!)
    }

    private fun stopVpn() {
        val intent = Intent(this, EchVpnService::class.java).apply {
            action = EchVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        viewModel.setConnected(false)
        localProxyAddr = null
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.saveConfig()
    }
}
