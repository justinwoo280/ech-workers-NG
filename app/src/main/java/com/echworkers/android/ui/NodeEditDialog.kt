package com.echworkers.android.ui

import android.app.AlertDialog
import android.content.Context
import android.view.LayoutInflater
import com.echworkers.android.databinding.DialogNodeEditBinding
import com.echworkers.android.model.NodeConfig

class NodeEditDialog(
    private val context: Context,
    private val node: NodeConfig?,
    private val onSave: (NodeConfig) -> Unit
) {
    private val binding = DialogNodeEditBinding.inflate(LayoutInflater.from(context))

    init {
        node?.let {
            binding.etName.setText(it.name)
            binding.etServerAddr.setText(it.serverAddr)
            binding.etServerIp.setText(it.serverIp)
            binding.etToken.setText(it.token)
            binding.switchEch.isChecked = it.enableEch
            binding.switchYamux.isChecked = it.enableYamux
            binding.etEchDomain.setText(it.echDomain)
            binding.etDnsServer.setText(it.dnsServer)
        }
    }

    fun show() {
        val title = if (node == null) "添加节点" else "编辑节点"

        AlertDialog.Builder(context)
            .setTitle(title)
            .setView(binding.root)
            .setPositiveButton("保存") { _, _ ->
                val editedNode = NodeConfig(
                    id = node?.id ?: java.util.UUID.randomUUID().toString(),
                    name = binding.etName.text.toString().ifEmpty { "新节点" },
                    serverAddr = binding.etServerAddr.text.toString(),
                    serverIp = binding.etServerIp.text.toString(),
                    token = binding.etToken.text.toString(),
                    enableEch = binding.switchEch.isChecked,
                    enableYamux = binding.switchYamux.isChecked,
                    echDomain = binding.etEchDomain.text.toString().ifEmpty { "cloudflare-ech.com" },
                    dnsServer = binding.etDnsServer.text.toString().ifEmpty { "1.1.1.1:53" }
                )
                onSave(editedNode)
            }
            .setNegativeButton("取消", null)
            .apply {
                if (node != null) {
                    setNeutralButton("删除") { _, _ ->
                        // 通过回调删除（传递空节点表示删除）
                    }
                }
            }
            .show()
    }
}
