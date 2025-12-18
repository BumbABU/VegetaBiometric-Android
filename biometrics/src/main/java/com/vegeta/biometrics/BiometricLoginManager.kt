package com.vegeta.biometrics

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.core.content.edit

object BiometricType {
    const val FINGERPRINT = 0
    const val FACE = 1
    const val IRIS = 2
}

class BiometricLoginManager (private  val context : Context)
{
    private val cryptographyManager: CryptographyManager = CryptographyManager()
    private val sharedPreferences: SharedPreferences = context.getSharedPreferences(Constants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)

    fun isBiometricAvailable () : Boolean
    {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }

    /*
    0 : BiometricManager.BIOMETRIC_SUCCESS (Biometrics available and enrolled)
    1 : BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE (No biometric hardware)
    2 : BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ( Biometric hardware unavailable)
    3 : BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED (No biometrics enrolled)
    11: BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ( Security update required)
    12: BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED (Biometrics unsupported)

    -1: undefined
    */

    fun getBiometricStatus (): Int {
        val  biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate((Authenticators.BIOMETRIC_STRONG))
    }

    fun getAvailableBiometricTypes(): IntArray {
        val result = mutableListOf<Int>()
        val pm = context.packageManager
        val biometricManager = BiometricManager.from(context)

        if(biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) {
            if(pm.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FINGERPRINT)) {
                result.add(BiometricType.FINGERPRINT)
            }

            if(pm.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FACE)) {
                result.add(BiometricType.FACE)
            }

            if(pm.hasSystemFeature(android.content.pm.PackageManager.FEATURE_IRIS)) {
                result.add(BiometricType.IRIS)
            }
        }

        return result.toIntArray()
    }

    fun hasSecretKeyValid(keyName : String): Boolean {
        if(cryptographyManager.hasKeyValid(keyName) == false) {
            sharedPreferences.edit {
                remove(keyName)
                apply()
            }
            return false
        }
        return true
    }

    fun hasSecretKey(keyName : String): Boolean {
        return cryptographyManager.hasKey((keyName))
    }

    fun persistSecureData(keyName: String, data: String) {
        val cipher = cryptographyManager.getInitCipherForEncrypt(keyName)
        val ciphertextWrapper = cryptographyManager.encryptData(data, cipher)
        cryptographyManager.persistCiphertextWrapperToSharedPrefs(
            ciphertextWrapper, context, Constants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, keyName
        )
    }

    fun requestSecureData(
        keyName: String,
        activity: FragmentActivity,
        callback: UnityBiometricCallback
    ) {
        if (!hasSecretKeyValid(keyName)) {
            callback.onFailure("KEY INVALID")
            return
        }

        // Lấy dữ liệu đã mã hóa từ SharedPreferences
        val ciphertextWrapper = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            context, Constants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, keyName
        )

        // ÉP TOÀN BỘ PHẦN HIỆN BIOMETRIC PROMPT CHẠY TRÊN MAIN THREAD
        activity.runOnUiThread {
            if (ciphertextWrapper == null) {
                callback.onFailure("NO CIPHERTEXT")  // Chưa lưu dữ liệu lần nào
                return@runOnUiThread
            }

            // Tạo cipher để decrypt (chỉ dùng khi biometric thành công)
            val decryptionCipher = try {
                cryptographyManager.getInitCipherForDecrypt(keyName, ciphertextWrapper.initVector)
            } catch (e: Exception) {
                callback.onFailure("INIT CIPHER_FAIL: ${e.message}")
                return@runOnUiThread
            }

            // Tạo BiometricPrompt
            val biometricPrompt = BiometricPromptUtils.createBiometricPrompt(activity) { result ->
                val authenticatedCipher = result.cryptoObject?.cipher
                if (authenticatedCipher == null) {
                    callback.onFailure("NO CRYPTO")
                    return@createBiometricPrompt
                }

                try {
                    val data = cryptographyManager.decryptData(
                        ciphertextWrapper.ciphertext,
                        authenticatedCipher
                    )
                    callback.onSuccess(data)
                } catch (e: Exception) {
                    callback.onFailure("DECRYPT FAIL: ${e.message}")
                }
            }

            // Tạo thông tin dialog
            val promptInfo = BiometricPromptUtils.createPromptInfo(
                title = "Login with biometrics",
                negative = "Cancel"
            )

            // Hiện dialog biometric
            try {
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(decryptionCipher))
            } catch (e: Exception) {
                callback.onFailure("Can not turn on biometric Prompt: ${e.message}")
            }
        }
    }

}
