package com.automaite.terminal

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import android.webkit.CookieManager
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ---------------------------------------------------------------------------
// Colours / dimensions (match app dark theme)
// ---------------------------------------------------------------------------
private const val BG_COLOR         = 0xFF0A0A0F.toInt()
private const val SURFACE_COLOR    = 0xFF16161F.toInt()
private const val CARD_COLOR       = 0xFF1E1E2E.toInt()
private const val ACCENT_COLOR     = 0xFF7C3AED.toInt()
private const val ACCENT_LIGHT     = 0xFF9D5EFF.toInt()
private const val TEXT_PRIMARY     = 0xFFEEEEF4.toInt()
private const val TEXT_SECONDARY   = 0xFF8888AA.toInt()
private const val DANGER_COLOR     = 0xFFEF4444.toInt()
private const val SUCCESS_COLOR    = 0xFF22C55E.toInt()
private const val DIVIDER_COLOR    = 0xFF2A2A3E.toInt()

private val CATEGORIES = listOf("api_key", "password", "token", "ssh_key", "other")

private fun categoryIcon(cat: String) = when (cat) {
    "api_key"  -> "⚿"
    "password" -> "🔑"
    "token"    -> "🎫"
    "ssh_key"  -> "🖧"
    else        -> "•"
}

// ---------------------------------------------------------------------------
// dp / sp helpers
// ---------------------------------------------------------------------------
private fun Context.dp(v: Int) = (v * resources.displayMetrics.density).toInt()
private fun Context.sp(v: Float) = TypedValue.applyDimension(
    TypedValue.COMPLEX_UNIT_SP, v, resources.displayMetrics
)

// ---------------------------------------------------------------------------
// VaultActivity
// ---------------------------------------------------------------------------
class VaultActivity : AppCompatActivity() {

    private lateinit var vault: EncryptedVault
    private lateinit var adapter: CredentialAdapter
    private val credentials = mutableListOf<CredentialMetadata>()

    // Deep-link approval params (set in onCreate if launched via deep link)
    private var approvalRequestId: String? = null
    private var approvalCredentialName: String? = null
    private var approvalReason: String? = null
    private var approvalAgentId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        vault = EncryptedVault(this)

        val uri = intent?.data
        if (uri != null && uri.scheme == "automaite" && uri.host == "vault") {
            // Deep-link: automaite://vault/approve?request_id=&credential_name=&reason=&agent_id=
            approvalRequestId    = uri.getQueryParameter("request_id")
            approvalCredentialName = uri.getQueryParameter("credential_name")
            approvalReason       = uri.getQueryParameter("reason")
            approvalAgentId      = uri.getQueryParameter("agent_id")

            if (approvalRequestId != null && approvalCredentialName != null) {
                showApprovalScreen(
                    requestId      = approvalRequestId!!,
                    credentialName = approvalCredentialName!!,
                    reason         = approvalReason ?: "",
                    agentId        = approvalAgentId ?: "unknown"
                )
                return
            }
        }

        showVaultListScreen()
    }

    // -----------------------------------------------------------------------
    // Vault list screen
    // -----------------------------------------------------------------------
    private fun showVaultListScreen() {
        val root = FrameLayout(this).apply {
            setBackgroundColor(BG_COLOR)
        }

        // Toolbar
        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(48), dp(16), dp(12))
            setBackgroundColor(SURFACE_COLOR)
        }
        val titleView = TextView(this).apply {
            text = "Credential Vault"
            setTextColor(TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        toolbar.addView(titleView)

        // RecyclerView
        val recycler = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@VaultActivity)
            setBackgroundColor(BG_COLOR)
        }

        adapter = CredentialAdapter(credentials,
            onEdit   = { meta -> showAddEditDialog(meta) },
            onDelete = { meta -> confirmDelete(meta) }
        )
        recycler.adapter = adapter

        // Swipe-to-delete
        val swipeHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            0, ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            override fun onMove(rv: RecyclerView, vh: RecyclerView.ViewHolder,
                                tgt: RecyclerView.ViewHolder) = false
            override fun onSwiped(vh: RecyclerView.ViewHolder, dir: Int) {
                val pos  = vh.adapterPosition
                val meta = credentials[pos]
                confirmDelete(meta) { deleted ->
                    if (!deleted) adapter.notifyItemChanged(pos) // restore if cancelled
                }
            }
        })
        swipeHelper.attachToRecyclerView(recycler)

        // FAB
        val fab = TextView(this).apply {
            text = "+"
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 28f)
            gravity = Gravity.CENTER
            setBackgroundColor(ACCENT_COLOR)
            val sz = dp(56)
            layoutParams = FrameLayout.LayoutParams(sz, sz).apply {
                gravity = Gravity.BOTTOM or Gravity.END
                setMargins(0, 0, dp(24), dp(24))
            }
        }
        fab.setOnClickListener { showAddEditDialog(null) }

        // Layout
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }
        content.addView(toolbar)
        content.addView(recycler, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        ))
        root.addView(content)
        root.addView(fab)

        setContentView(root)
        refreshList()
    }

    private fun refreshList() {
        credentials.clear()
        credentials.addAll(vault.getAllCredentials())
        adapter.notifyDataSetChanged()
    }

    // -----------------------------------------------------------------------
    // Add / Edit dialog
    // -----------------------------------------------------------------------
    private fun showAddEditDialog(existing: CredentialMetadata?) {
        val isEdit = existing != null
        val ctx    = this

        val layout = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(8))
            setBackgroundColor(CARD_COLOR)
        }

        fun styledEdit(hint: String, inputType: Int = InputType.TYPE_CLASS_TEXT): EditText =
            EditText(ctx).apply {
                this.hint = hint
                this.inputType = inputType
                setTextColor(TEXT_PRIMARY)
                setHintTextColor(TEXT_SECONDARY)
                setBackgroundColor(SURFACE_COLOR)
                setPadding(dp(12), dp(10), dp(12), dp(10))
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(12) }
                layoutParams = lp
            }

        val nameEdit  = styledEdit("Name").apply { setText(existing?.name ?: "") }
        val valueEdit = styledEdit(
            "Value (secret)",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        )

        // Category spinner
        val catLabel = TextView(ctx).apply {
            text = "Category"
            setTextColor(TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(4) }
            layoutParams = lp
        }
        val catSpinner = Spinner(ctx).apply {
            val arr = ArrayAdapter(ctx, android.R.layout.simple_spinner_item, CATEGORIES)
            arr.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            adapter = arr
            existing?.category?.let { setSelection(CATEGORIES.indexOf(it).coerceAtLeast(0)) }
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
            layoutParams = lp
        }

        // Allowed agents field (comma-separated)
        val agentsEdit = styledEdit("Allowed agents (comma-separated)").apply {
            setText(existing?.allowedAgents?.joinToString(", ") ?: "")
        }

        layout.addView(nameEdit)
        layout.addView(valueEdit)
        layout.addView(catLabel)
        layout.addView(catSpinner)
        layout.addView(agentsEdit)

        AlertDialog.Builder(this)
            .setTitle(if (isEdit) "Edit Credential" else "Add Credential")
            .setView(layout)
            .setPositiveButton(if (isEdit) "Save" else "Add") { _, _ ->
                val name     = nameEdit.text.toString().trim()
                val value    = valueEdit.text.toString()
                val category = CATEGORIES[catSpinner.selectedItemPosition]
                val agents   = agentsEdit.text.toString()
                    .split(",").map { it.trim() }.filter { it.isNotEmpty() }

                if (name.isEmpty()) {
                    Toast.makeText(this, "Name is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                if (isEdit) {
                    vault.updateCredential(existing!!.id, name, category, agents)
                    if (value.isNotEmpty()) {
                        // If user entered a new value, re-save with it
                        // (requires biometric since we're writing to encrypted prefs)
                        BiometricHelper.authenticate(
                            this, "Authenticate to save",
                            "Biometric needed to update credential value",
                            onSuccess = {
                                // value update: delete & re-save preserving id metadata is
                                // complex; simplest approach is to save a new entry and delete old
                                vault.saveCredential(name, value, category, agents)
                                vault.deleteCredential(existing.id)
                                refreshList()
                            },
                            onError = { err ->
                                Toast.makeText(this, "Auth failed: $err", Toast.LENGTH_SHORT).show()
                                refreshList()
                            }
                        )
                    } else {
                        refreshList()
                    }
                } else {
                    if (value.isEmpty()) {
                        Toast.makeText(this, "Value is required", Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    BiometricHelper.authenticate(
                        this, "Authenticate to save",
                        "Biometric required to store new credential",
                        onSuccess = {
                            vault.saveCredential(name, value, category, agents)
                            refreshList()
                        },
                        onError = { err ->
                            Toast.makeText(this, "Auth failed: $err", Toast.LENGTH_SHORT).show()
                        }
                    )
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // -----------------------------------------------------------------------
    // Delete helpers
    // -----------------------------------------------------------------------
    private fun confirmDelete(meta: CredentialMetadata, callback: ((Boolean) -> Unit)? = null) {
        AlertDialog.Builder(this)
            .setTitle("Delete \"${meta.name}\"?")
            .setMessage("This cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                vault.deleteCredential(meta.id)
                refreshList()
                callback?.invoke(true)
            }
            .setNegativeButton("Cancel") { _, _ -> callback?.invoke(false) }
            .show()
    }

    // -----------------------------------------------------------------------
    // Approval screen (deep-linked from agent request)
    // -----------------------------------------------------------------------
    private fun showApprovalScreen(
        requestId: String,
        credentialName: String,
        reason: String,
        agentId: String
    ) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG_COLOR)
            setPadding(dp(24), dp(60), dp(24), dp(24))
            gravity = Gravity.TOP
        }

        fun label(text: String, color: Int = TEXT_SECONDARY, sizeSp: Float = 12f) =
            TextView(this).apply {
                this.text = text
                setTextColor(color)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(4) }
                layoutParams = lp
            }

        fun value(text: String) = TextView(this).apply {
            this.text = text
            setTextColor(TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(null, Typeface.BOLD)
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(20) }
            layoutParams = lp
        }

        val titleView = TextView(this).apply {
            text = "Credential Request"
            setTextColor(TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTypeface(null, Typeface.BOLD)
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(32) }
            layoutParams = lp
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(CARD_COLOR)
            setPadding(dp(20), dp(20), dp(20), dp(20))
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(32) }
            layoutParams = lp
        }
        card.addView(label("Agent"))
        card.addView(value(agentId))
        card.addView(label("Credential requested"))
        card.addView(value(credentialName))
        card.addView(label("Reason"))
        card.addView(value(reason.ifBlank { "No reason provided" }))

        // Button row
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            layoutParams = lp
        }

        fun styledBtn(text: String, bgColor: Int) = TextView(this).apply {
            this.text = text
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(null, Typeface.BOLD)
            gravity = Gravity.CENTER
            setBackgroundColor(bgColor)
            val lp = LinearLayout.LayoutParams(0, dp(52), 1f).apply {
                marginEnd = if (text == "Deny") 0 else dp(12)
            }
            layoutParams = lp
        }

        val denyBtn    = styledBtn("Deny",    DANGER_COLOR)
        val approveBtn = styledBtn("Approve", ACCENT_COLOR)

        denyBtn.setOnClickListener {
            sendApprovalResponse(requestId, approved = false, encryptedValue = null)
        }

        approveBtn.setOnClickListener {
            BiometricHelper.authenticate(
                activity  = this,
                title     = "Confirm credential release",
                subtitle  = "Authenticate to send \"$credentialName\" to $agentId",
                onSuccess = {
                    // Find the credential by name
                    val meta = vault.getAllCredentials().firstOrNull {
                        it.name.equals(credentialName, ignoreCase = true)
                    }
                    if (meta == null) {
                        Toast.makeText(
                            this, "Credential \"$credentialName\" not found", Toast.LENGTH_LONG
                        ).show()
                        sendApprovalResponse(requestId, approved = false, encryptedValue = null)
                        return@authenticate
                    }
                    val rawValue = vault.getCredentialValue(meta.id)
                    if (rawValue == null) {
                        Toast.makeText(this, "Could not read credential value", Toast.LENGTH_LONG)
                            .show()
                        sendApprovalResponse(requestId, approved = false, encryptedValue = null)
                        return@authenticate
                    }
                    vault.recordUsage(meta.id)
                    // Encrypt value for transit then POST to relay
                    val encrypted = encryptForTransit(rawValue)
                    if (encrypted == null) {
                        Toast.makeText(
                            this, "No vault key — link this device first", Toast.LENGTH_LONG
                        ).show()
                        sendApprovalResponse(requestId, approved = false, encryptedValue = null)
                        return@authenticate
                    }
                    sendApprovalResponse(requestId, approved = true, encryptedValue = encrypted)
                },
                onError = { err ->
                    Toast.makeText(this, "Authentication failed: $err", Toast.LENGTH_LONG).show()
                }
            )
        }

        btnRow.addView(denyBtn)
        btnRow.addView(approveBtn)

        root.addView(titleView)
        root.addView(card)
        root.addView(btnRow)

        setContentView(root)
    }

    // -----------------------------------------------------------------------
    // Transit encryption — AES-256-GCM with HKDF-derived key from device_secret
    // -----------------------------------------------------------------------
    private fun encryptForTransit(plaintext: String): String? {
        val deviceSecret = getDeviceSecret()
        if (deviceSecret == null) {
            Log.e("VaultActivity", "No device_secret — cannot encrypt credential for transit")
            return null
        }

        // Derive AES-256-GCM key using HKDF-SHA256 (same params as crypto.py + app.js)
        val key = deriveAesKey(deviceSecret)

        // Encrypt with AES-256-GCM
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce) // 128-bit tag
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        // Wire format: nonce (12) + ciphertext + tag (appended by GCM)
        val result = ByteArray(nonce.size + ciphertext.size)
        System.arraycopy(nonce, 0, result, 0, nonce.size)
        System.arraycopy(ciphertext, 0, result, nonce.size, ciphertext.size)

        return android.util.Base64.encodeToString(result, android.util.Base64.NO_WRAP)
    }

    private fun getDeviceSecret(): String? = readDeviceSecret(this)

    /**
     * HKDF-SHA256 key derivation matching crypto.py and app.js.
     * Salt: "automaite-e2ee-v1", Info: "aes-key", Output: 32 bytes.
     */
    private fun deriveAesKey(deviceSecret: String): ByteArray {
        val salt = "automaite-e2ee-v1".toByteArray(Charsets.UTF_8)
        val info = "aes-key".toByteArray(Charsets.UTF_8)
        val ikm = deviceSecret.toByteArray(Charsets.UTF_8)

        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        // HKDF-Expand: OKM = T(1) where T(1) = HMAC-SHA256(PRK, info || 0x01)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(0x01.toByte())
        return mac.doFinal()
    }

    private fun sendApprovalResponse(requestId: String, approved: Boolean, encryptedValue: String?) {
        val relayBase = "https://term.automaite.ca"
        val body = JSONObject().apply {
            put("approved", approved)
            if (approved && encryptedValue != null) {
                put("encrypted_credential", encryptedValue)
            }
        }
        val requestBody = body.toString().toRequestBody("application/json".toMediaType())
        // Attach the WebView session cookie so the relay can authenticate the request
        val cookieStr = CookieManager.getInstance().getCookie(relayBase) ?: ""

        Thread {
            try {
                val client = OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .build()
                val reqBuilder = Request.Builder()
                    .url("$relayBase/api/vault/respond/$requestId")
                    .post(requestBody)
                if (cookieStr.isNotEmpty()) reqBuilder.header("Cookie", cookieStr)
                client.newCall(reqBuilder.build()).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e("VaultActivity", "Relay returned ${response.code} for vault respond")
                    } else {
                        Log.d("VaultActivity", "Relay response: ${response.code}")
                    }
                }
            } catch (e: Exception) {
                Log.e("VaultActivity", "Failed to send vault response: ${e.message}")
            }
            runOnUiThread {
                val msg = if (approved) "Credential sent" else "Request denied"
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
                finish()
            }
        }.start()
    }
}

// ---------------------------------------------------------------------------
// RecyclerView adapter
// ---------------------------------------------------------------------------
class CredentialAdapter(
    private val items: List<CredentialMetadata>,
    private val onEdit: (CredentialMetadata) -> Unit,
    private val onDelete: (CredentialMetadata) -> Unit
) : RecyclerView.Adapter<CredentialAdapter.VH>() {

    inner class VH(val root: LinearLayout) : RecyclerView.ViewHolder(root) {
        val icon     : TextView = root.getChildAt(0) as TextView
        val nameView : TextView = (root.getChildAt(1) as LinearLayout).getChildAt(0) as TextView
        val metaView : TextView = (root.getChildAt(1) as LinearLayout).getChildAt(1) as TextView
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val ctx  = parent.context

        val icon = TextView(ctx).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 24f)
            gravity = Gravity.CENTER
            val sz = ctx.dp(48)
            layoutParams = LinearLayout.LayoutParams(sz, sz).apply { marginEnd = ctx.dp(12) }
        }

        val info = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val nameView = TextView(ctx).apply {
            setTextColor(TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setTypeface(null, Typeface.BOLD)
        }
        val metaView = TextView(ctx).apply {
            setTextColor(TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        info.addView(nameView)
        info.addView(metaView)

        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(CARD_COLOR)
            setPadding(ctx.dp(16), ctx.dp(14), ctx.dp(16), ctx.dp(14))
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = ctx.dp(1)
            }
            layoutParams = lp
        }
        row.addView(icon)
        row.addView(info)

        return VH(row)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        holder.icon.text = categoryIcon(item.category)
        holder.nameView.text = item.name

        val lastUsedStr = if (item.lastUsed > 0) {
            val diff = System.currentTimeMillis() - item.lastUsed
            when {
                diff < 60_000L          -> "just now"
                diff < 3_600_000L       -> "${diff / 60_000} min ago"
                diff < 86_400_000L      -> "${diff / 3_600_000} hr ago"
                else                    -> "${diff / 86_400_000} d ago"
            }
        } else "never used"

        holder.metaView.text = "${item.category}  •  ${item.useCount}× used  •  $lastUsedStr"

        holder.root.setOnClickListener { onEdit(item) }
        holder.root.setOnLongClickListener { onDelete(item); true }
    }

    override fun getItemCount() = items.size
}
