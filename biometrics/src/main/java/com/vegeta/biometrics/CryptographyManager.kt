package com.vegeta.biometrics

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import com.google.gson.Gson
import androidx.core.content.edit

interface CryptographyManager
{
    fun getInitializedCipherForEncryption (keyName : String) : Cipher

    fun getInitializedCipherForDecryption (keyName: String, initializationVector: ByteArray) : Cipher

    fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper

    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String

    fun persistCiphertextWrapperToSharedPrefs(
        ciphertextWrapper: CiphertextWrapper,
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    )

    fun getCiphertextWrapperFromSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ): CiphertextWrapper?
}

fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()

private class CryptographyManagerImpl : CryptographyManager
{
    override fun getInitializedCipherForEncryption(keyName: String): Cipher
    {
        val cipher = getCipher()
        val secretKey =  getOrCreateSecretKey(keyName)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    override fun getInitializedCipherForDecryption(keyName: String, initializationVector: ByteArray): Cipher
    {
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey(keyName)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        return cipher
    }

    override fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper
    {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    override fun decryptData(
        ciphertext: ByteArray,
        cipher: Cipher
    ): String
    {
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charset.forName(("UTF-8")))
    }

    override fun persistCiphertextWrapperToSharedPrefs(
        ciphertextWrapper: CiphertextWrapper,
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    )
    {
        val json = Gson().toJson(ciphertextWrapper)
        context.getSharedPreferences(filename, mode).edit { putString(prefKey, json) }
    }

    override fun getCiphertextWrapperFromSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ): CiphertextWrapper
    {
        val json = context.getSharedPreferences(filename, mode).getString(prefKey, null)
        return Gson().fromJson(json, CiphertextWrapper::class.java)
    }

    private fun getCipher(): Cipher {
        val transformation = "$BiometricConstants.ENCRYPTION_ALGORITHM/$BiometricConstants.ENCRYPTION_BLOCK_MODE/$BiometricConstants.ENCRYPTION_PADDING"
        return Cipher.getInstance(transformation)
    }

    private fun getOrCreateSecretKey(keyName: String): SecretKey
    {
        // If SecretKey was previously created for that keyName, then grab and return it.

        val keyStore = KeyStore.getInstance(BiometricConstants.ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        // if you reach here, then a new SecretKey must be generated for that keyName
        val paramsBuilder = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setBlockModes(BiometricConstants.ENCRYPTION_BLOCK_MODE)
            setEncryptionPaddings(BiometricConstants.ENCRYPTION_PADDING)
            setKeySize(BiometricConstants.KEY_SIZE)
            setUserAuthenticationRequired(true)
        }

        val keyGenParams = paramsBuilder.build()
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            BiometricConstants.ANDROID_KEYSTORE
        )

        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }
}

data class CiphertextWrapper(val ciphertext: ByteArray, val initializationVector: ByteArray)