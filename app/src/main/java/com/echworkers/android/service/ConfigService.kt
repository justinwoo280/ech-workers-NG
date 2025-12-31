package com.echworkers.android.service

import android.content.Context
import com.echworkers.android.model.AppConfig
import com.google.gson.Gson
import java.io.File

class ConfigService(private val context: Context) {

    private val gson = Gson()
    private val configFile: File
        get() = File(context.filesDir, "config.json")

    fun load(): AppConfig {
        return try {
            if (configFile.exists()) {
                val json = configFile.readText()
                gson.fromJson(json, AppConfig::class.java) ?: AppConfig()
            } else {
                AppConfig()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            AppConfig()
        }
    }

    fun save(config: AppConfig) {
        try {
            val json = gson.toJson(config)
            configFile.writeText(json)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
