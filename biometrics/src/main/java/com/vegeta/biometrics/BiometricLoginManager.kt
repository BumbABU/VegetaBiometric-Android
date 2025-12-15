package com.vegeta.biometrics

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore

class BiometricLoginManager (private  val context : Context)
{
    private val cryptographyManager: CryptographyManager = CryptographyManager()
    private val sharedPreferences: SharedPreferences = context.getSharedPreferences(BiometricConstants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)

    fun isBiometricAvailable () : Boolean
    {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun isBiometricAvailable2 (): Int {
        val biometricManager = BiometricManager.from(context)
        return when (biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> 0
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> 1
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> 2
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> 3
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> 4
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> 5
            else -> -1
        }
    }

    fun getBiometricTypes(): List<Int> {
        val types = mutableListOf<Int>()
        val biometricManager = BiometricManager.from(context)

        // Check strong biometrics (fingerprint/face)
        if (biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) {
            // Note: Android không expose trực tiếp loại cụ thể, nhưng ta có thể infer qua capability
            // Để chính xác hơn, có thể dùng PackageManager để check FEATURE_FINGERPRINT, FEATURE_FACE, etc.
            if (context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FINGERPRINT)) {
                types.add(0)
                // Fingerprint Recognition
            }
            if (context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FACE)) {
                types.add(1)
                // Face Recognition
            }
            if (context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_IRIS)) {
                types.add(2)
                // Iris Recognition
            }
        }
        return types
    }

    fun hasValidKeyAndToken(): Boolean {
        // Check if key exists in Keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val keyExists = keyStore.containsAlias(BiometricConstants.KEY_NAME)

        if (!keyExists) {
            // "No secret key in Keystore"
            return false
        }

        // Check if ciphertext exists in SharedPrefs
        val ciphertextWrapper = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            context, BiometricConstants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, BiometricConstants.CIPHERTEXT_WRAPPER
        )

        if (ciphertextWrapper == null) {
            //"No encrypted token stored"
            return false
        }

        // Optional: Try to init cipher to verify key validity (e.g., not invalidated)
        return try {
           cryptographyManager.getInitializedCipherForDecryption(BiometricConstants.KEY_NAME, ciphertextWrapper.initializationVector)
            true
        } catch (e: Exception) {
             false
        }
    }

    fun saveTokenOnFirstLogin(token: String) {
        val cipher = cryptographyManager.getInitializedCipherForEncryption(BiometricConstants.KEY_NAME)
        val ciphertextWrapper = cryptographyManager.encryptData(token, cipher)
        cryptographyManager.persistCiphertextWrapperToSharedPrefs(
            ciphertextWrapper, context, BiometricConstants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, BiometricConstants.CIPHERTEXT_WRAPPER
        )
    }

    fun loginWithBiometrics(
        activity: FragmentActivity,
        onSuccess: (String) -> Unit,
        onFailure: (String) -> Unit
    ) {
        if (!hasValidKeyAndToken()) {
            onFailure("Failure = not valid ")
            return
        }

        // 2. Lấy ciphertext đã lưu
        val ciphertextWrapper = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            context, BiometricConstants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, BiometricConstants.CIPHERTEXT_WRAPPER
        )

        if (ciphertextWrapper == null) {
            onFailure("Failer  cipher text wrapper = null")
            return
        }

        // 3. Tạo cipher để giải mã (chỉ dùng được sau khi xác thực sinh trắc học)
        val decryptionCipher = try {
            cryptographyManager.getInitializedCipherForDecryption(BiometricConstants.KEY_NAME, ciphertextWrapper.initializationVector)
        } catch (e: Exception) {
            onFailure("decrypt fail")
            return
        }

        // 4. Tạo BiometricPrompt
        val biometricPrompt = BiometricPromptUtils.createBiometricPrompt(activity) { result ->
            val authenticatedCipher = result.cryptoObject?.cipher
            if (authenticatedCipher == null) {
                onFailure("fail")
                return@createBiometricPrompt
            }

            try {
                val decryptedToken = cryptographyManager.decryptData(
                    ciphertextWrapper.ciphertext,
                    authenticatedCipher
                )
                onSuccess(decryptedToken)
            } catch (e: Exception) {
                onFailure("decryption fail : ${e.message}")
            }
        }

        // 5. Hiển thị dialog
        val promptInfo = BiometricPromptUtils.createPromptInfo(
            title = "Login with biometrics",
            negative = "cancel"
        )

        try {
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(decryptionCipher))
        } catch (e: Exception) {
            onFailure("Không thể hiển thị xác thực sinh trắc học")
        }
    }

}
