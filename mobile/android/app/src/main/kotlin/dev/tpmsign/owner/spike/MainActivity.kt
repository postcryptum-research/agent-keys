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
package dev.tpmsign.owner.spike

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
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
        /** owner-core `user_op::tests`: the golden operation's userOpHash on chain 31337 (anvil). */
        const val GOLDEN_DIGEST_HEX = "48e286b71f896beef7a0b4d23fd82d6afae60a64e7976118de492a2fba4c1947"
        const val GOLDEN_MESSAGE = "TPM_sign: P0 golden userOpHash (owner-core user_op test, chain 31337)"
        val P256_N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val P256_HALF_N: BigInteger = P256_N.shiftRight(1)
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
        val wipe = Button(this).apply { text = "Delete the key"; setOnClickListener { safely { deleteKey() } } }
        column.addView(create); column.addView(sign); column.addView(wipe); column.addView(out)
        setContentView(ScrollView(this).apply { addView(column) })

        say("Android API ${Build.VERSION.SDK_INT}")
        say("StrongBox feature: ${packageManager.hasSystemFeature("android.hardware.strongbox_keystore")}")
        val bm = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        say("BIOMETRIC_STRONG available: ${bm == BiometricManager.BIOMETRIC_SUCCESS} (code $bm)")
        if (keyStore.containsAlias(ALIAS)) { say("key $ALIAS exists"); describeKey() } else say("no key yet")
    }

    // ---- 1. key creation (design §5.2) -------------------------------------

    private fun createKey() {
        if (keyStore.containsAlias(ALIAS)) { say("key exists; delete it first"); return }
        val challenge = MessageDigest.getInstance("SHA-256").digest("TPM_sign/P0/enroll".toByteArray())
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
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
        say("key created; tier by creation path: $tier")
        describeKey()
        exportAttestation()
    }

    private fun describeKey() {
        val priv = keyStore.getKey(ALIAS, null) as PrivateKey
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
        val (x, y) = publicXY()
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

    private fun publicXY(): Pair<String, String> {
        val pub = keyStore.getCertificate(ALIAS).publicKey as ECPublicKey
        return Pair(pub.w.affineX.hex32(), pub.w.affineY.hex32())
    }

    private fun exportAttestation() {
        val chain = keyStore.getCertificateChain(ALIAS)
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
                        |  "backend": "android-keystore-$tier",
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

    private fun deleteKey() {
        if (keyStore.containsAlias(ALIAS)) { keyStore.deleteEntry(ALIAS); say("key deleted") } else say("no key")
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
