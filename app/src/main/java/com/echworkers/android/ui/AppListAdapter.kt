package com.echworkers.android.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.echworkers.android.databinding.ItemAppBinding

class AppListAdapter(
    private val selectedApps: MutableSet<String>,
    private val onSelectionChanged: (String, Boolean) -> Unit
) : ListAdapter<ApplicationInfo, AppListAdapter.ViewHolder>(AppDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemAppBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ViewHolder(
        private val binding: ItemAppBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(appInfo: ApplicationInfo) {
            val pm = binding.root.context.packageManager
            binding.ivAppIcon.setImageDrawable(appInfo.loadIcon(pm))
            binding.tvAppName.text = pm.getApplicationLabel(appInfo)
            binding.tvPackageName.text = appInfo.packageName
            
            // 先移除 listener 再设置状态，避免触发回调
            binding.checkbox.setOnCheckedChangeListener(null)
            binding.checkbox.isChecked = selectedApps.contains(appInfo.packageName)

            binding.root.setOnClickListener {
                binding.checkbox.isChecked = !binding.checkbox.isChecked
            }

            binding.checkbox.setOnCheckedChangeListener { _, isChecked ->
                onSelectionChanged(appInfo.packageName, isChecked)
            }
        }
    }

    class AppDiffCallback : DiffUtil.ItemCallback<ApplicationInfo>() {
        override fun areItemsTheSame(oldItem: ApplicationInfo, newItem: ApplicationInfo): Boolean {
            return oldItem.packageName == newItem.packageName
        }

        override fun areContentsTheSame(oldItem: ApplicationInfo, newItem: ApplicationInfo): Boolean {
            return oldItem.packageName == newItem.packageName
        }
    }
}
