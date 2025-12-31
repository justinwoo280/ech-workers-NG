package com.echworkers.android.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.echworkers.android.R
import com.echworkers.android.databinding.ItemNodeBinding
import com.echworkers.android.model.NodeConfig

class NodeAdapter(
    private val onItemClick: (NodeConfig) -> Unit,
    private val onItemLongClick: (NodeConfig) -> Unit
) : ListAdapter<NodeConfig, NodeAdapter.ViewHolder>(NodeDiffCallback()) {

    private var selectedNodeId: String? = null

    fun setSelectedNode(node: NodeConfig?) {
        val oldId = selectedNodeId
        selectedNodeId = node?.id
        
        currentList.forEachIndexed { index, item ->
            if (item.id == oldId || item.id == selectedNodeId) {
                notifyItemChanged(index)
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemNodeBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val node = getItem(position)
        holder.bind(node, node.id == selectedNodeId)
    }

    inner class ViewHolder(
        private val binding: ItemNodeBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(node: NodeConfig, isSelected: Boolean) {
            binding.tvNodeName.text = node.name
            binding.tvNodeAddr.text = node.serverAddr

            val features = mutableListOf<String>()
            if (node.enableEch) features.add("ECH")
            if (node.enableYamux) features.add("Yamux")
            binding.tvNodeFeatures.text = features.joinToString(" | ")

            // 选中状态通过 stroke 显示
            binding.cardRoot.strokeWidth = if (isSelected) 4 else 0
            binding.cardRoot.setStrokeColor(ContextCompat.getColorStateList(binding.root.context, R.color.accent))

            binding.cardRoot.setOnClickListener {
                onItemClick(node)
            }

            binding.cardRoot.setOnLongClickListener {
                onItemLongClick(node)
                true
            }
        }
    }

    class NodeDiffCallback : DiffUtil.ItemCallback<NodeConfig>() {
        override fun areItemsTheSame(oldItem: NodeConfig, newItem: NodeConfig): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: NodeConfig, newItem: NodeConfig): Boolean {
            return oldItem == newItem
        }
    }
}
