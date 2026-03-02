package com.automaite.terminal

import android.annotation.SuppressLint
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    private val baseUrl = "https://term.automaite.ca"

    /** JS interface exposed as window.AutomaiteApp */
    inner class WebAppInterface {
        @JavascriptInterface
        fun openInBrowser(url: String) {
            Log.d("Automaite", "Opening in browser: $url")
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        }

        @JavascriptInterface
        fun storeDeviceSecret(deviceId: String, secret: String) {
            Log.d("Automaite", "Storing device secret for device: ${deviceId.take(8)}...")
            writeDeviceSecret(this@MainActivity, deviceId, secret)
        }

        @JavascriptInterface
        fun openVault() {
            Log.d("Automaite", "Opening VaultActivity")
            startActivity(Intent(this@MainActivity, VaultActivity::class.java))
        }
    }

    @SuppressLint("SetJavaScriptEnabled", "AddJavascriptInterface")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Fullscreen immersive
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val controller = WindowInsetsControllerCompat(window, window.decorView)
        controller.hide(WindowInsetsCompat.Type.systemBars())
        controller.systemBarsBehavior =
            WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE

        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Enable WebView debugging only in debug builds
        WebView.setWebContentsDebuggingEnabled(
            0 != (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE)
        )

        webView = WebView(this).apply {
            setBackgroundColor(0xFF0A0A0F.toInt())
        }
        setContentView(webView)

        // Enable third-party cookies
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(webView, true)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            cacheMode = WebSettings.LOAD_DEFAULT
            useWideViewPort = true
            loadWithOverviewMode = true
            setSupportZoom(false)
            builtInZoomControls = false
            displayZoomControls = false
            mediaPlaybackRequiresUserGesture = false
            javaScriptCanOpenWindowsAutomatically = true
            userAgentString = userAgentString + " AutomaiteApp/1.1"
        }

        // Expose JS interface for opening system browser
        webView.addJavascriptInterface(WebAppInterface(), "AutomaiteApp")

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView?,
                request: WebResourceRequest?
            ): Boolean {
                val url = request?.url?.toString() ?: return false
                // Keep navigation within term.automaite.ca inside the WebView
                if (url.startsWith(baseUrl)) return false
                // Open external links in browser
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                return true
            }

            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                super.onPageStarted(view, url, favicon)
                Log.d("Automaite", "Page loading: $url")
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                Log.d("Automaite", "Page loaded: $url")
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: WebResourceError?
            ) {
                val url = request?.url?.toString() ?: "unknown"
                val desc = error?.description?.toString() ?: "unknown error"
                Log.e("Automaite", "Error loading $url: $desc")
                if (request?.isForMainFrame == true) {
                    Toast.makeText(this@MainActivity, "Load error: $desc", Toast.LENGTH_LONG).show()
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(msg: ConsoleMessage?): Boolean {
                Log.d("Automaite", "JS: ${msg?.message()} [${msg?.sourceId()}:${msg?.lineNumber()}]")
                return true
            }
        }

        // Handle deep link or load base URL
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIntent(it) }
    }

    private fun handleIntent(intent: Intent) {
        val uri = intent.data
        if (uri != null && uri.scheme == "automaite") {
            when (uri.host) {
                "auth" -> {
                    // Deep link from browser after Google Sign-In:
                    // automaite://auth?token=XXX
                    val token = uri.getQueryParameter("token")
                    if (token != null) {
                        Log.d("Automaite", "Auth deep link received, exchanging token")
                        webView.loadUrl("$baseUrl/api/app/exchange?token=$token")
                    } else {
                        webView.loadUrl(baseUrl)
                    }
                }
                "pair" -> {
                    // Deep link: automaite://pair?token=XYZ
                    val token = uri.getQueryParameter("token")
                        ?: uri.pathSegments.firstOrNull()
                    val pairUrl = if (token != null) {
                        "$baseUrl/pair?token=$token"
                    } else {
                        "$baseUrl/pair"
                    }
                    webView.loadUrl(pairUrl)
                }
                else -> webView.loadUrl(baseUrl)
            }
        } else if (!::webView.isInitialized || webView.url == null) {
            webView.loadUrl(baseUrl)
        }
    }

    @Deprecated("Use onBackPressedDispatcher")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }

    override fun onResume() {
        super.onResume()
        webView.onResume()
    }

    override fun onPause() {
        webView.onPause()
        super.onPause()
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }
}
