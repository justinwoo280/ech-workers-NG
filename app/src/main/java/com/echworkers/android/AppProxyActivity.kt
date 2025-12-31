package com.echworkers.android

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.echworkers.android.databinding.ActivityAppProxyBinding
import com.echworkers.android.service.ConfigService
import com.echworkers.android.ui.AppListAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppProxyActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAppProxyBinding
    private lateinit var adapter: AppListAdapter
    private val configService by lazy { ConfigService(this) }
    private var selectedApps = mutableSetOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAppProxyBinding.inflate(layoutInflater)
        setContentView(binding.root)

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "分应用代理"

        setupUI()
        loadApps()
    }

    private fun setupUI() {
        val config = configService.load()
        selectedApps = config.perAppProxyApps.toMutableSet()

        binding.switchEnable.isChecked = config.perAppProxyEnabled
        binding.rgMode.check(
            if (config.perAppProxyMode == "whitelist") R.id.rbWhitelist else R.id.rbBlacklist
        )

        adapter = AppListAdapter(selectedApps) { packageName, isSelected ->
            if (isSelected) {
                selectedApps.add(packageName)
            } else {
                selectedApps.remove(packageName)
            }
        }

        binding.recyclerApps.layoutManager = LinearLayoutManager(this)
        binding.recyclerApps.adapter = adapter

        binding.btnSave.setOnClickListener {
            saveConfig()
            finish()
        }
    }

    private fun loadApps() {
        lifecycleScope.launch {
            val apps = withContext(Dispatchers.IO) {
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                    .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
                    .sortedBy { packageManager.getApplicationLabel(it).toString() }
            }
            adapter.submitList(apps)
        }
    }

    private fun saveConfig() {
        val config = configService.load()
        config.perAppProxyEnabled = binding.switchEnable.isChecked
        config.perAppProxyMode = if (binding.rbWhitelist.isChecked) "whitelist" else "blacklist"
        config.perAppProxyApps = selectedApps.toMutableList()
        configService.save(config)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }
}
