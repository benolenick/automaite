package com.automaite.terminal

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class CredentialMetadata(
    val id: String,
    val name: String,
    val category: String,
    val createdAt: Long,
    val lastUsed: Long,
    val useCount: Int,
    val allowedAgents: List<String>,
    val autoApprove: Boolean
)

class EncryptedVault(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .setUserAuthenticationRequired(true, 30)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "automaite_vault",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    // --- Internal JSON helpers ---

    private fun credToJson(
        id: String,
        name: String,
        value: String,
        category: String,
        createdAt: Long,
        lastUsed: Long,
        useCount: Int,
        allowedAgents: List<String>,
        autoApprove: Boolean
    ): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("value", value)
        put("category", category)
        put("createdAt", createdAt)
        put("lastUsed", lastUsed)
        put("useCount", useCount)
        put("allowedAgents", JSONArray(allowedAgents))
        put("autoApprove", autoApprove)
    }

    private fun jsonToMetadata(obj: JSONObject): CredentialMetadata {
        val agentsArr = obj.optJSONArray("allowedAgents") ?: JSONArray()
        val agents = (0 until agentsArr.length()).map { agentsArr.getString(it) }
        return CredentialMetadata(
            id = obj.getString("id"),
            name = obj.getString("name"),
            category = obj.optString("category", "other"),
            createdAt = obj.optLong("createdAt", 0L),
            lastUsed = obj.optLong("lastUsed", 0L),
            useCount = obj.optInt("useCount", 0),
            allowedAgents = agents,
            autoApprove = obj.optBoolean("autoApprove", false)
        )
    }

    private fun loadRaw(id: String): JSONObject? {
        val json = prefs.getString(id, null) ?: return null
        return runCatching { JSONObject(json) }.getOrNull()
    }

    private fun saveRaw(id: String, obj: JSONObject) {
        prefs.edit().putString(id, obj.toString()).apply()
        addToIndex(id)
    }

    // Index: a comma-separated list of all credential IDs stored under key "__index__"
    private fun getIndex(): MutableSet<String> {
        val raw = prefs.getString("__index__", "") ?: ""
        return if (raw.isBlank()) mutableSetOf() else raw.split(",").toMutableSet()
    }

    private fun addToIndex(id: String) {
        val index = getIndex()
        index.add(id)
        prefs.edit().putString("__index__", index.joinToString(",")).apply()
    }

    private fun removeFromIndex(id: String) {
        val index = getIndex()
        index.remove(id)
        prefs.edit().putString("__index__", index.joinToString(",")).apply()
    }

    // --- Public API ---

    /**
     * Returns metadata for all stored credentials. No biometric required.
     * Values are never included.
     */
    fun getAllCredentials(): List<CredentialMetadata> {
        return getIndex()
            .filter { it.isNotBlank() }
            .mapNotNull { id -> loadRaw(id)?.let { jsonToMetadata(it) } }
            .sortedByDescending { it.lastUsed }
    }

    /**
     * Returns the secret value for a credential. Caller MUST ensure BiometricPrompt
     * succeeded before calling this — the EncryptedSharedPreferences master key
     * requires recent user authentication.
     */
    fun getCredentialValue(id: String): String? {
        return loadRaw(id)?.optString("value", null)
    }

    /**
     * Saves a new credential and returns its generated ID.
     */
    fun saveCredential(
        name: String,
        value: String,
        category: String,
        allowedAgents: List<String>
    ): String {
        val id = "cred_${UUID.randomUUID()}"
        val now = System.currentTimeMillis()
        val obj = credToJson(
            id = id,
            name = name,
            value = value,
            category = category,
            createdAt = now,
            lastUsed = 0L,
            useCount = 0,
            allowedAgents = allowedAgents,
            autoApprove = false
        )
        saveRaw(id, obj)
        return id
    }

    /**
     * Updates mutable fields of an existing credential (null = keep existing).
     */
    fun updateCredential(
        id: String,
        name: String? = null,
        category: String? = null,
        allowedAgents: List<String>? = null
    ) {
        val obj = loadRaw(id) ?: return
        name?.let { obj.put("name", it) }
        category?.let { obj.put("category", it) }
        allowedAgents?.let { agents ->
            obj.put("allowedAgents", JSONArray(agents))
        }
        saveRaw(id, obj)
    }

    /**
     * Deletes a credential by ID.
     */
    fun deleteCredential(id: String) {
        prefs.edit().remove(id).apply()
        removeFromIndex(id)
    }

    /**
     * Increments use count and updates lastUsed timestamp.
     */
    fun recordUsage(id: String) {
        val obj = loadRaw(id) ?: return
        obj.put("useCount", obj.optInt("useCount", 0) + 1)
        obj.put("lastUsed", System.currentTimeMillis())
        saveRaw(id, obj)
    }
}
