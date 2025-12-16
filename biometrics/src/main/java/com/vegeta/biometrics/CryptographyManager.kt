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
    fun getInitCipherForEncrypt (keyName : String) : Cipher

    fun getInitCipherForDecrypt (keyName: String, initializationVector: ByteArray) : Cipher

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
    public override fun getInitCipherForEncrypt(keyName: String): Cipher
    {
        val cipher = getCipher()
        val secretKey =  getOrCreateSecretKey(keyName)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    public override fun getInitCipherForDecrypt(keyName: String, initializationVector: ByteArray): Cipher
    {
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey(keyName)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        return cipher
    }

    public override fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper
    {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    public override fun decryptData(
        ciphertext: ByteArray,
        cipher: Cipher
    ): String
    {
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charset.forName(("UTF-8")))
    }

    public override fun persistCiphertextWrapperToSharedPrefs(
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

    public override fun getCiphertextWrapperFromSharedPrefs(
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
        val transformation = "$Constants.ENCRYPTION_ALGORITHM/$Constants.ENCRYPTION_BLOCK_MODE/$Constants.ENCRYPTION_PADDING"
        return Cipher.getInstance(transformation)
    }

    private fun getOrCreateSecretKey(keyName: String): SecretKey
    {
        // If SecretKey was previously created for that keyName, then grab and return it.

        val keyStore = KeyStore.getInstance(Constants.ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        // if you reach here, then a new SecretKey must be generated for that keyName
        val paramsBuilder = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setBlockModes(Constants.ENCRYPTION_BLOCK_MODE)
            setEncryptionPaddings(Constants.ENCRYPTION_PADDING)
            setKeySize(Constants.KEY_SIZE)
            setUserAuthenticationRequired(true)  // Key unlock only biometrics vetification success
            // setInvalidatedByBiometricEnrollment(true) // SecretKey automatically invalid when biometrics update ,...
            //
        }

        val keyGenParams = paramsBuilder.build()
        val keyGenerator = KeyGenerator.getInstance(
            Constants.ENCRYPTION_ALGORITHM,
            Constants.ANDROID_KEYSTORE
        )

        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }
}

data class CiphertextWrapper(val ciphertext: ByteArray, val initVector: ByteArray)