package com.automaite.terminal

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

private const val SECURE_PREFS_NAME = "automaite_vault_secure"
private const val LEGACY_PREFS_NAME = "automaite_vault"

private fun openSecurePrefs(context: Context): SharedPreferences? = try {
    val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    EncryptedSharedPreferences.create(
        context,
        SECURE_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
} catch (e: Exception) {
    Log.e("SecurePrefs", "Failed to open EncryptedSharedPreferences", e)
    null
}

/**
 * Read device_secret from encrypted prefs.
 * On first run after upgrade, migrates the value from legacy plaintext prefs and wipes it there.
 */
fun readDeviceSecret(context: Context): String? {
    val secure = openSecurePrefs(context) ?: return null
    val secret = secure.getString("device_secret", null)
    if (secret != null) return secret

    // Migration: check legacy plaintext prefs
    val legacy = context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
    val legacySecret = legacy.getString("device_secret", null) ?: return null
    // Migrate to encrypted prefs and wipe from plaintext
    secure.edit().putString("device_secret", legacySecret).apply()
    legacy.edit().remove("device_secret").apply()
    Log.i("SecurePrefs", "Migrated device_secret from legacy plaintext prefs")
    return legacySecret
}

/**
 * Store device_id and device_secret in encrypted prefs. Wipes legacy plaintext prefs.
 */
fun writeDeviceSecret(context: Context, deviceId: String, deviceSecret: String) {
    val secure = openSecurePrefs(context)
    if (secure == null) {
        Log.e("SecurePrefs", "EncryptedSharedPreferences unavailable — device_secret NOT persisted")
        return
    }
    secure.edit()
        .putString("device_id", deviceId)
        .putString("device_secret", deviceSecret)
        .apply()
    // Wipe legacy plaintext file
    context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
        .edit().remove("device_secret").remove("device_id").apply()
}
