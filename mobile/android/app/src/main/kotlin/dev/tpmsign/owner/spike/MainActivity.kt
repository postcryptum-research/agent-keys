// P0 spike (docs/MOBILE_OWNER_PLAN.md, phase P0; docs/MOBILE_OWNER_DESIGN.md §5.2,
// §5.6): does this phone's secure hardware sign a raw 32-byte digest with a
// P-256 key, behind a biometric check, in a form P256Validator accepts?
//
// What it does, and nothing more:
//   1. says which tier the key will get — StrongBox or TEE only — with the
//      notice from §5.6;
//   2. creates the key with the design's exact parameters and exports the
//      slot's attestation chain (DER files) for the laptop to verify;
//   3. signs the golden userOpHash from owner-core's tests with
//      NONEwithECDSA inside a BiometricPrompt, converts DER to r‖s, normalizes
//      low-s, and writes a vector JSON the repository's tests understand.
// Files land in the app's external files directory: `adb pull` them.
//
// P1 (design §2.1, §3, §4): button 4 enrolls this phone for an account from
// the laptop's enrollment QR — a NEW key per account (§5.1), attested with a
// challenge bound to the request (§5.2), the §5.6 notice acknowledged first;
// button 3 signs a root operation for an enrolled account behind the
// fingerprint prompt (blind until P2 decodes on the phone).
package dev.tpmsign.owner.spike

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.Base64
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class MainActivity : AppCompatActivity() {
    companion object {
        const val TAG = "tpmsign-p0"
        const val ALIAS = "tpmsign-p0-owner"
        /** One key per enrolled account (§5.1): alias by chain and account. */
        fun aliasFor(chainId: String, account: String) = "tpmsign-owner-$chainId-${account.lowercase()}"
        const val APP_VERSION = "0.0.3-p1"
        const val PREFS = "enrollments"
        /** owner-core `user_op::tests`: the golden operation's userOpHash on chain 31337 (anvil). */
        const val GOLDEN_DIGEST_HEX = "48e286b71f896beef7a0b4d23fd82d6afae60a64e7976118de492a2fba4c1947"
        const val GOLDEN_MESSAGE = "TPM_sign: P0 golden userOpHash (owner-core user_op test, chain 31337)"
        val P256_N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val P256_HALF_N: BigInteger = P256_N.shiftRight(1)
        const val MAX_REQUEST_BYTES = 64 * 1024
    }

    private lateinit var out: TextView
    private val keyStore: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    /** The tier the key creation path gave us (§5.6: on API 30 this is how we know). */
    private var tier: String = "none"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        out = TextView(this).apply { setTextIsSelectable(true); textSize = 13f }
        val create = Button(this).apply { text = "1. Create the owner key"; setOnClickListener { safely { createKey() } } }
        val sign = Button(this).apply { text = "2. Sign the golden digest (fingerprint)"; setOnClickListener { safely { signGolden() } } }
        val wipe = Button(this).apply { text = "Delete the P0 key"; setOnClickListener { safely { deleteKey() } } }
        val wipeTest = Button(this).apply { text = "Delete test-chain enrollments (anvil 31337)"; setOnClickListener { safely { deleteTestEnrollments() } } }
        val scan = Button(this).apply { text = "3. Scan the laptop's QR and sign (P1)"; setOnClickListener { safely { startScan() } } }
        val enroll = Button(this).apply { text = "4. Enroll this phone for an account (P1)"; setOnClickListener { safely { startScan(enrollOnly = true) } } }
        column.addView(create); column.addView(sign); column.addView(scan); column.addView(enroll); column.addView(wipe); column.addView(wipeTest); column.addView(out)
        setContentView(ScrollView(this).apply { addView(column) })

        say("Android API ${Build.VERSION.SDK_INT}")
        say("StrongBox feature: ${packageManager.hasSystemFeature("android.hardware.strongbox_keystore")}")
        val bm = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        say("BIOMETRIC_STRONG available: ${bm == BiometricManager.BIOMETRIC_SUCCESS} (code $bm)")
        if (keyStore.containsAlias(ALIAS)) { say("key $ALIAS exists"); describeKey() } else say("no key yet")
        listEnrollments()
    }

    // ---- 1. key creation (design §5.2) -------------------------------------

    private fun createKey() {
        if (keyStore.containsAlias(ALIAS)) { say("key exists; delete it first"); return }
        generateKey(ALIAS, MessageDigest.getInstance("SHA-256").digest("TPM_sign/P0/enroll".toByteArray()))
        say("key created; tier by creation path: $tier")
        describeKey(ALIAS)
        exportAttestation(ALIAS)
    }

    /** §5.2's parameters; StrongBox first, the TEE on StrongBoxUnavailableException. Sets [tier]. */
    private fun generateKey(alias: String, challenge: ByteArray) {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // NONE for P256Validator today, SHA256 for plan B (§11.1): both set at creation
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // a biometric check on every use (D2: biometric only by default)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        tier = try {
            kpg.initialize(spec(true)); kpg.generateKeyPair(); "strongbox"
        } catch (e: StrongBoxUnavailableException) {
            say("StrongBox unavailable (${e.message}); retrying in the TEE")
            kpg.initialize(spec(false)); kpg.generateKeyPair(); "tee"
        }
        // API 31+ confirms the tier from the key itself (§5.6)
        val priv = keyStore.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(priv.algorithm, "AndroidKeyStore").getKeySpec(priv, KeyInfo::class.java)
        require(info.isInsideSecureHardware) { "the key is not in secure hardware; refusing to use it" }
        if (Build.VERSION.SDK_INT >= 31) {
            tier = when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                else -> "unknown(${info.securityLevel})"
            }
        }
    }

    private fun describeKey(alias: String = ALIAS) {
        val priv = keyStore.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(priv.algorithm, "AndroidKeyStore").getKeySpec(priv, KeyInfo::class.java)
        say("isInsideSecureHardware: ${info.isInsideSecureHardware}")
        if (Build.VERSION.SDK_INT >= 31) {
            val lvl = when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TRUSTED_ENVIRONMENT"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "UNKNOWN_SECURE"
                else -> "UNKNOWN(${info.securityLevel})"
            }
            say("KeyInfo.securityLevel (API 31+): $lvl")
            tier = when (lvl) { "STRONGBOX" -> "strongbox"; "TRUSTED_ENVIRONMENT" -> "tee"; else -> lvl.lowercase() }
        }
        say("user auth required: ${info.isUserAuthenticationRequired}, validity ${info.userAuthenticationValidityDurationSeconds}s, auth type ${info.userAuthenticationType}")
        val (x, y) = publicXY(alias)
        say("public key\n  x = 0x$x\n  y = 0x$y")
        say(notice())
    }

    /** The §5.6 notice. */
    private fun notice(): String = when (tier) {
        "strongbox" -> "This phone keeps the owner key in a separate secure chip (StrongBox)."
        "tee" -> "NOTICE — this phone keeps keys in its processor's trusted mode (TEE), not in a separate " +
            "secure chip. The key cannot be copied and signs only after your fingerprint, but a bug in the " +
            "trusted OS or a physical attack on the chip could reach it. A phone with StrongBox, or an iPhone, " +
            "protects the owner key better. (docs/MOBILE_OWNER_DESIGN.md §5.6)"
        else -> "WARNING — key tier $tier: not hardware-backed. Do not use this phone as an owner key."
    }

    private fun publicXY(alias: String = ALIAS): Pair<String, String> {
        val pub = keyStore.getCertificate(alias).publicKey as ECPublicKey
        return Pair(pub.w.affineX.hex32(), pub.w.affineY.hex32())
    }

    private fun exportAttestation(alias: String) {
        val chain = keyStore.getCertificateChain(alias)
        val dir = filesDir()
        chain.forEachIndexed { i, c -> File(dir, "attest-$i.der").writeBytes(c.encoded) }
        say("attestation chain: ${chain.size} certificates → ${dir.path}/attest-*.der")
    }

    // ---- 2. signing (design §5.2: NONEwithECDSA inside a BiometricPrompt) --

    private fun signGolden() {
        if (!keyStore.containsAlias(ALIAS)) { say("create the key first"); return }
        val digest = GOLDEN_DIGEST_HEX.hexToBytes()
        val priv = keyStore.getKey(ALIAS, null) as PrivateKey
        val sig = Signature.getInstance("NONEwithECDSA").apply { initSign(priv) }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                safely {
                    val s = result.cryptoObject!!.signature!!
                    s.update(digest)
                    val der = s.sign()
                    val (r, sv) = derToRs(der)
                    val sLow = if (sv > P256_HALF_N) P256_N.subtract(sv) else sv
                    val (x, y) = publicXY()
                    val json = """
                        |{
                        |  "backend": "android-keystore",
                        |  "tier": "$tier",
                        |  "message": "$GOLDEN_MESSAGE",
                        |  "digest": "0x$GOLDEN_DIGEST_HEX",
                        |  "r": "0x${r.hex32()}",
                        |  "s": "0x${sLow.hex32()}",
                        |  "x": "0x$x",
                        |  "y": "0x$y"
                        |}
                        |""".trimMargin()
                    File(filesDir(), "p0-vector.json").writeText(json)
                    say("signed after biometric; DER ${der.size} bytes; low-s applied: ${sLow != sv}")
                    say(json)
                    say("→ ${filesDir().path}/p0-vector.json")
                    Log.i(TAG, json)
                }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) { say("biometric error $code: $msg") }
            override fun onAuthenticationFailed() { say("biometric not recognised, try again") }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign a root operation")
            .setSubtitle("userOpHash 0x${GOLDEN_DIGEST_HEX.take(8)}…${GOLDEN_DIGEST_HEX.takeLast(6)}")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(sig))
    }

    // ---- 3. P1: the LAN session (design §3, §4) — blind signing of the
    // laptop's userOpHash after the commitment check. Decoding and display of
    // the operation (P2) come with owner-core on the phone.

    private var enrollOnly = false
    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents
        if (text == null) say("scan cancelled") else safely { handleQr(text) }
    }

    private fun startScan(enrollOnly: Boolean = false) {
        this.enrollOnly = enrollOnly
        scanLauncher.launch(ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(if (enrollOnly) "Scan the enrollment QR shown by agent-signer key create --phone" else "Scan the QR shown by agent-signer")
            setBeepEnabled(false)
            setOrientationLocked(false)
        })
    }

    /** `tpmsign:1?u=<url>&h=<commitment>`; the host must be a local address (§3.2). */
    private fun handleQr(uri: String) {
        require(uri.startsWith("tpmsign:1?")) { "not a tpmsign:1 QR" }
        val params = uri.removePrefix("tpmsign:1?").split("&")
            .mapNotNull { it.split("=", limit = 2).takeIf { p -> p.size == 2 } }.associate { it[0] to it[1] }
        val url = params["u"] ?: error("no u= in the QR")
        val commitment = params["h"] ?: error("no h= in the QR")
        val host = URL(url).host
        require(URL(url).protocol == "http" && isLocalHost(host)) { "session host $host is not a local address; refusing" }
        say("session: $url")
        Thread {
            try {
                val bytes = httpGet(url)
                val got = b64url(sha256(bytes))
                require(got == commitment) { "the served request does not match the QR's commitment; refusing" }
                val kind = JSONObject(String(bytes)).getString("tpmSign")
                runOnUiThread {
                    safely {
                        when (kind) {
                            "enroll-request" -> reviewAndEnroll(bytes, commitment, url)
                            "sign-request" -> { require(!enrollOnly) { "this is a sign request, not an enrollment; use button 3" }; reviewAndSign(bytes, commitment, url) }
                            else -> error("unknown request type $kind")
                        }
                    }
                }
            } catch (e: Exception) {
                runOnUiThread { say("ERROR ${e::class.java.simpleName}: ${e.message}") }
            }
        }.start()
    }

    private fun reviewAndSign(bytes: ByteArray, commitment: String, url: String) {
        val req = JSONObject(String(bytes))
        require(req.getString("tpmSign") == "sign-request") { "not a sign request" }
        require(req.getInt("version") == 1) { "protocol version ${req.getInt("version")} not supported" }
        val now = System.currentTimeMillis() / 1000
        require(now <= req.getLong("expires") + 300) { "the request has expired" }
        val op = req.getJSONObject("userOp")
        val nonce = java.math.BigInteger(op.getString("nonce"))
        require(nonce.shiftRight(64).signum() == 0) { "not a root-path operation (nonce key != 0); refusing" }
        require(op.getString("initCode") == "0x") { "operations with initCode are refused (v1)" }
        val laptop = req.getJSONObject("laptop")
        val hashHex = laptop.getString("userOpHash").removePrefix("0x")
        require(hashHex.length == 64) { "bad userOpHash" }
        // the key enrolled for this account (§5.1); the P0 key as the fallback for accounts enrolled by hand
        val enrolled = aliasFor(req.getString("chainId"), op.getString("sender"))
        val alias = if (keyStore.containsAlias(enrolled)) enrolled else ALIAS
        require(keyStore.containsAlias(alias)) { "no key for this account on this phone: enroll it first (button 4)" }
        // P1 shows what it has; P2 decodes the calldata and recomputes the hash on the phone.
        say("REVIEW (P1, blind)\n  chain ${req.getString("chainId")}\n  account ${op.getString("sender")}\n  key ${if (alias == ALIAS) "P0 key" else "enrolled key"}\n  nonce $nonce\n  callData ${op.getString("callData").take(74)}…\n  laptop says: ${laptop.optString("command", "?")}\n  userOpHash 0x$hashHex")
        val priv = keyStore.getKey(alias, null) as PrivateKey
        val sig = Signature.getInstance("NONEwithECDSA").apply { initSign(priv) }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                safely {
                    val s = result.cryptoObject!!.signature!!
                    s.update(hashHex.hexToBytes())
                    val (r, sv) = derToRs(s.sign())
                    val sLow = if (sv > P256_HALF_N) P256_N.subtract(sv) else sv
                    val (x, y) = publicXY(alias)
                    val resp = JSONObject()
                        .put("tpmSign", "sign-response").put("version", 1).put("request", commitment)
                        .put("result", "signed").put("userOpHash", "0x$hashHex")
                        .put("signature", "0x${r.hex32()}${sLow.hex32()}")
                        .put("publicKey", JSONObject().put("x", "0x$x").put("y", "0x$y"))
                        .put("app", appInfo())
                    Thread {
                        try {
                            val code = httpPost(url, resp.toString().toByteArray())
                            runOnUiThread { say("signed and posted: HTTP $code") }
                        } catch (e: Exception) { runOnUiThread { say("POST failed: ${e.message}") } }
                    }.start()
                }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                say("biometric error $code: $msg — telling the laptop")
                val refusal = JSONObject().put("tpmSign", "sign-response").put("version", 1).put("request", commitment)
                    .put("result", "refused").put("reason", "user").put("detail", msg.toString())
                Thread { try { httpPost(url, refusal.toString().toByteArray()) } catch (_: Exception) {} }.start()
            }
            override fun onAuthenticationFailed() { say("biometric not recognised, try again") }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder().setTitle("Sign a root operation")
                .setSubtitle("userOpHash 0x${hashHex.take(8)}…${hashHex.takeLast(6)}")
                .setNegativeButtonText("Refuse")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).build(),
            BiometricPrompt.CryptoObject(sig)
        )
    }

    // ---- 4. P1: enrollment (design §2.1, §4.3, §5.2, §5.6) --------------------

    private fun reviewAndEnroll(bytes: ByteArray, commitment: String, url: String) {
        val req = JSONObject(String(bytes))
        require(req.getInt("version") == 1) { "protocol version ${req.getInt("version")} not supported" }
        val now = System.currentTimeMillis() / 1000
        require(now <= req.getLong("expires") + 300) { "the request has expired" }
        val chainId = req.getString("chainId"); val account = req.getString("account"); val label = req.getString("label")
        require(label.length in 1..64) { "bad label" }
        val alias = aliasFor(chainId, account)
        require(!keyStore.containsAlias(alias)) { "this phone already holds a key for $account on chain $chainId; a new key needs a handover from the current one (§5.4)" }
        // the tier this phone can give, before the user confirms (§5.6): a dry look, no key yet
        val strongBox = packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
        val tierNotice = if (strongBox) "This phone has StrongBox: the key will live in a separate secure chip."
            else "NOTICE — this phone has no StrongBox. The key will live in the processor's trusted mode (TEE): " +
                "it cannot be copied and signs only after your fingerprint, but a bug in the trusted OS or a physical " +
                "attack on the chip could reach it. A phone with StrongBox, or an iPhone, protects an owner key better."
        say("ENROLLMENT\n  chain $chainId\n  account $account\n  label $label\n  entryPoint ${req.getString("entryPoint")}\n  $tierNotice")
        AlertDialog.Builder(this)
            .setTitle("Enroll this phone as the owner key?")
            .setMessage("Account $account on chain $chainId, label \"$label\".\n\n$tierNotice\n\nA new key is created on this phone for this account. Nothing changes on-chain until the laptop hands root to it.")
            .setNegativeButton("Refuse") { _, _ ->
                say("enrollment refused — telling the laptop")
                val refusal = JSONObject().put("tpmSign", "enroll-response").put("version", 1).put("request", commitment)
                    .put("result", "refused").put("reason", "user").put("detail", "declined on the phone").put("app", appInfo())
                Thread { try { httpPost(url, refusal.toString().toByteArray()) } catch (_: Exception) {} }.start()
            }
            .setPositiveButton(if (strongBox) "Enroll" else "I understand, enroll") { _, _ ->
                safely {
                    // the attestation challenge binds the key to this exact request (§5.2)
                    val challenge = sha256("TPM_sign/v1/enroll".toByteArray() + commitment.toByteArray())
                    generateKey(alias, challenge)
                    val (x, y) = publicXY(alias)
                    val chain = keyStore.getCertificateChain(alias)
                    val attestation = org.json.JSONArray().also { arr -> chain.forEach { arr.put(Base64.getEncoder().encodeToString(it.encoded)) } }
                    val resp = JSONObject()
                        .put("tpmSign", "enroll-response").put("version", 1).put("request", commitment)
                        .put("result", "enrolled")
                        .put("publicKey", JSONObject().put("x", "0x$x").put("y", "0x$y"))
                        .put("securityLevel", tier).put("deviceCredential", false)
                        .put("attestation", attestation).put("app", appInfo())
                    // the enrollment record (§5.4): nothing secret
                    prefs().edit().putString(alias, JSONObject().put("label", label).put("chainId", chainId).put("account", account)
                        .put("entryPoint", req.getString("entryPoint")).put("tier", tier).put("x", "0x$x").put("y", "0x$y")
                        .put("enrolledAt", now).toString()).apply()
                    say("enrolled: tier $tier, ${chain.size} attestation certificates\n  x = 0x$x\n  y = 0x$y\n  fingerprint ${fingerprint(x, y)}  ← compare with the laptop")
                    Thread {
                        try {
                            val code = httpPost(url, resp.toString().toByteArray())
                            runOnUiThread { say("enrollment posted: HTTP $code. Next, on the laptop: owner set-root … --expect-fingerprint ${fingerprint(x, y)}") }
                        } catch (e: Exception) { runOnUiThread { say("POST failed: ${e.message}") } }
                    }.start()
                }
            }
            .setCancelable(false)
            .show()
    }

    private fun listEnrollments() {
        val all = prefs().all
        if (all.isEmpty()) { say("no enrolled accounts"); return }
        for ((alias, v) in all) {
            val e = JSONObject(v.toString())
            val present = if (keyStore.containsAlias(alias)) "" else " (KEY MISSING — biometric re-enrolled or key deleted)"
            say("enrolled: ${e.getString("label")} — account ${e.getString("account")} on chain ${e.getString("chainId")}, tier ${e.getString("tier")}$present\n  fingerprint ${fingerprint(e.getString("x").removePrefix("0x"), e.getString("y").removePrefix("0x"))}")
        }
    }

    private fun prefs() = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun appInfo() = JSONObject().put("platform", "android").put("version", APP_VERSION).put("core", "none")

    /** owner-core `fingerprint`: the first 100 bits of sha256(x ‖ y), base32, four groups of five. */
    private fun fingerprint(xHex: String, yHex: String): String {
        val h = sha256(xHex.hexToBytes() + yHex.hexToBytes())
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val sb = StringBuilder()
        var acc = 0; var bits = 0; var i = 0
        while (sb.length < 20) {
            if (bits < 5) { acc = (acc shl 8) or (h[i++].toInt() and 0xff); bits += 8 }
            bits -= 5
            sb.append(alphabet[(acc shr bits) and 31])
        }
        return sb.chunked(5).joinToString("-")
    }

    /** §3.2: an IP literal (no name, so no DNS and no rebinding) that is private, link-local or ULA. */
    private fun isLocalHost(host: String): Boolean {
        val h = host.trim('[', ']')
        val literal = h.matches(Regex("^[0-9.]+$")) || h.matches(Regex("^[0-9a-fA-F:]+$"))
        if (!literal) return false
        val a = try { InetAddress.getByName(h) } catch (_: Exception) { return false }
        return a.isSiteLocalAddress || a.isLinkLocalAddress ||
            (a is java.net.Inet6Address && (a.address[0].toInt() and 0xfe) == 0xfc)
    }

    /** The request is a few KiB; anything past 64 KiB is not ours. */
    private fun httpGet(url: String): ByteArray {
        val c = (URL(url).openConnection() as HttpURLConnection).apply { connectTimeout = 10000; readTimeout = 10000; useCaches = false }
        try {
            require(c.responseCode == 200) { "HTTP ${c.responseCode}" }
            val body = c.inputStream.readNBytes(MAX_REQUEST_BYTES + 1)
            require(body.size <= MAX_REQUEST_BYTES) { "the request exceeds ${MAX_REQUEST_BYTES / 1024} KiB; refusing" }
            return body
        } finally { c.disconnect() }
    }

    private fun httpPost(url: String, body: ByteArray): Int {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"; doOutput = true; connectTimeout = 10000; readTimeout = 10000
            setRequestProperty("Content-Type", "application/json")
        }
        try { c.outputStream.use { it.write(body) }; return c.responseCode } finally { c.disconnect() }
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    private fun b64url(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun deleteKey() {
        if (keyStore.containsAlias(ALIAS)) { keyStore.deleteEntry(ALIAS); say("key deleted") } else say("no key")
    }

    /** Development only: a local anvil is recreated on every run, so its accounts recur with new owners. */
    private fun deleteTestEnrollments() {
        val gone = prefs().all.filter { JSONObject(it.value.toString()).getString("chainId") == "31337" }.keys
        if (gone.isEmpty()) { say("no test-chain enrollments"); return }
        val ed = prefs().edit()
        for (alias in gone) { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias); ed.remove(alias) }
        ed.apply()
        say("deleted ${gone.size} test-chain enrollment(s) and their keys")
    }

    // ---- helpers -------------------------------------------------------------

    private fun filesDir(): File = (getExternalFilesDir(null) ?: filesDir).also { it.mkdirs() }

    private fun safely(block: () -> Unit) {
        try { block() } catch (e: Exception) { say("ERROR ${e::class.java.simpleName}: ${e.message}"); Log.e(TAG, "failed", e) }
    }

    private fun say(line: String) { out.append(line + "\n\n"); Log.i(TAG, line) }

    /** SEQUENCE { INTEGER r, INTEGER s } → (r, s). Minimal DER as the Keystore emits it. */
    private fun derToRs(der: ByteArray): Pair<BigInteger, BigInteger> {
        require(der[0] == 0x30.toByte()) { "not a DER sequence" }
        var i = 2
        if ((der[1].toInt() and 0x80) != 0) i = 2 + (der[1].toInt() and 0x7f)
        require(der[i] == 0x02.toByte()) { "r is not an INTEGER" }
        val rl = der[i + 1].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(i + 2, i + 2 + rl))
        i += 2 + rl
        require(der[i] == 0x02.toByte()) { "s is not an INTEGER" }
        val sl = der[i + 1].toInt() and 0xff
        val s = BigInteger(1, der.copyOfRange(i + 2, i + 2 + sl))
        require(i + 2 + sl == der.size) { "trailing bytes in DER" }
        return Pair(r, s)
    }

    private fun BigInteger.hex32(): String = toString(16).padStart(64, '0').takeLast(64)
    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
