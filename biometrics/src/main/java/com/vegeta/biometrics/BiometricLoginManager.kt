package com.vegeta.biometrics

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.core.content.edit

object  ErrCode {
    const val KEY_NOT_EXIST = 1
    const val KEY_INVALID = 2
    const val NO_DATA = 3
    const val CANCELED = 4
    const val LOCKED = 5
    const val OTHER = 99
    const val  INTERNAL = 100
}

object  ErrString {
    const val KEY_NOT_EXIST = "Secure key does not exist"
    const val KEY_INVALID = "Secure key is invalid"
    const val NO_DATA = "No secure data available"
    const val  CANCELED = "Authentication was cancelled"
    const val  LOCKED = "Biometric authentication is temporarily locked"
    const val  OTHER = "Other"
    const val  INTERNAL = "Internal"
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

    fun getSecretKeyState(keyName: String): Int {
        val keyState = cryptographyManager.getKeyState(keyName)
        if(keyState == KeyState.InValid) {
            sharedPreferences.edit {
                remove(keyName)
                apply()
            }
        }
        return keyState
    }

//    fun persistSecureData(keyName: String, data: String) {
//        val cipher = cryptographyManager.getInitCipherForEncrypt(keyName)
//        val ciphertextWrapper = cryptographyManager.encryptData(data, cipher)
//        cryptographyManager.persistCiphertextWrapperToSharedPrefs(
//            ciphertextWrapper, context, Constants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, keyName
//        )
//    }

    fun persistSecureDataWithBiometric(
        keyName: String,
        data: String,
        activity: FragmentActivity,
        callback: UnityBiometricCallback,
        inValidEnroll : Boolean) {

        val cipher = try {
            cryptographyManager.getInitCipherForEncrypt(keyName, inValidEnroll)
        } catch (e : Exception) {
            callback.onFailure(ErrCode.INTERNAL, "${ErrString.INTERNAL} 1 : ${e.message}")
            return
        }

        activity.runOnUiThread {
            val  biometricPrompt = BiometricPromptUtils.createBiometricPrompt(
                activity,
                onSuccess = { result ->
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if(authenticatedCipher == null) {
                        callback.onFailure(ErrCode.INTERNAL,"${ErrString.INTERNAL} : NO CRYPTO")
                        return@createBiometricPrompt
                    }

                    try {
                        val wrapper = cryptographyManager.encryptData(
                            data,
                            authenticatedCipher
                        )

                        cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                            wrapper,
                            activity,
                            Constants.SHARED_PREFS_FILENAME,
                            Context.MODE_PRIVATE,
                            keyName
                        )

                        callback.onSuccess("Encrypt Success")
                    } catch (e: Exception) {
                        callback.onFailure(
                            ErrCode.INTERNAL,
                            "${ErrString.INTERNAL} 2 : ${e.message}"
                        )
                    }

                },
                onError = { code, msg ->
                    when (code) {
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                            callback.onFailure(ErrCode.LOCKED, ErrString.LOCKED)
                        }

                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED -> {
                            callback.onFailure(ErrCode.CANCELED, ErrString.CANCELED)
                        }

                        else -> {
                            callback.onFailure(
                                ErrCode.OTHER,
                                "${ErrString.OTHER} : ${msg}"
                            )
                        }
                    }

                }
            )

            val promptInfo = BiometricPromptUtils.createPromptInfo(
                title = "Confirm biometrics",
                negative = "Cancel"
            )

            try {
                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(cipher)
                )
            } catch (e: Exception) {
                callback.onFailure(
                    ErrCode.INTERNAL,
                    "${ErrString.INTERNAL} can not turn on biometric Prompt: ${e.message}"
                )
            }
        }
    }

    fun requestSecureData(
        keyName: String,
        activity: FragmentActivity,
        callback: UnityBiometricCallback
    ) {
        val keyState = getSecretKeyState(keyName)
        when(keyState) {
            KeyState.NonExist -> {
                callback.onFailure(ErrCode.KEY_NOT_EXIST, ErrString.KEY_NOT_EXIST)
                return
            }

            KeyState.InValid -> {
                callback.onFailure(ErrCode.KEY_INVALID, ErrString.KEY_INVALID)
                return
            }

           else -> {
               // do nothing
           }
        }

        val ciphertextWrapper = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            context, Constants.SHARED_PREFS_FILENAME, Context.MODE_PRIVATE, keyName
        )

        if (ciphertextWrapper == null) {
            callback.onFailure(ErrCode.NO_DATA, ErrString.NO_DATA)
            return
        }

        activity.runOnUiThread {
            val decryptionCipher = try {
                cryptographyManager.getInitCipherForDecrypt(keyName, ciphertextWrapper.initVector)
            } catch (e: Exception) {
                callback.onFailure(ErrCode.INTERNAL,"${ErrString.INTERNAL} 3 : ${e.message}")
                return@runOnUiThread
            }

           val biometricPrompt = BiometricPromptUtils.createBiometricPrompt(
                activity,

                onSuccess = { result ->
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        callback.onFailure(ErrCode.INTERNAL,"${ErrString.INTERNAL} : NO CRYPTO")
                        return@createBiometricPrompt
                    }

                    try {
                        val data = cryptographyManager.decryptData(
                            ciphertextWrapper.ciphertext,
                            authenticatedCipher
                        )
                        callback.onSuccess(data)
                    } catch (e: Exception) {
                        callback.onFailure(ErrCode.INTERNAL,"${ErrString.INTERNAL} 4 : ${e.message}")
                    }
                },
                onError = { code, msg ->
                    when (code) {
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                            callback.onFailure(ErrCode.LOCKED, ErrString.LOCKED)
                        }

                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED -> {
                            callback.onFailure(ErrCode.CANCELED, ErrString.CANCELED)
                        }

                        BiometricPrompt.ERROR_TIMEOUT,
                        BiometricPrompt.ERROR_VENDOR -> {
                            callback.onFailure(
                                ErrCode.OTHER,
                                "${ErrString.OTHER} : ${msg.toString()}"
                            )
                        }

                        else -> {
                            callback.onFailure(ErrCode.OTHER, "${ErrString.OTHER} : ${msg.toString()}")
                        }
                    }
                }
            )

            val promptInfo = BiometricPromptUtils.createPromptInfo(
                title = "Login with biometrics",
                negative = "Cancel"
            )

            try {
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(decryptionCipher))
            } catch (e: Exception) {
                callback.onFailure(ErrCode.INTERNAL, "${ErrString.INTERNAL} can not turn on biometric Prompt: ${e.message}")
            }
        }
    }

}

/* Not use now

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
 */

