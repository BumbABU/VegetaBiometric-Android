package com.vegeta.biometrics

import android.security.keystore.KeyProperties

object BiometricConstants
{
    public const val KEY_SIZE = 256
    public const val ANDROID_KEYSTORE = "AndroidKeyStore"
    public const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
    public const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
    public const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES

    public const val  SHARED_PREFS_FILENAME = "biometric_prefs"
    public const val CIPHERTEXT_WRAPPER = "ciphertext_wrapper"
    public const val KEY_NAME = "biometric_key"

}