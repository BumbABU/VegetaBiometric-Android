package com.vegeta.biometrics

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import com.google.gson.Gson
import androidx.core.content.edit


object KeyState {
    const val NonExist = 0
    const val InValid = 1
    const val Valid = 2
}

interface CryptographyManager
{
    fun getInitCipherForEncrypt (keyName : String, inValidEnroll: Boolean) : Cipher

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

    fun getKeyState (keyName: String) : Int
}

fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()

private class CryptographyManagerImpl : CryptographyManager
{
    public override fun getInitCipherForEncrypt(keyName: String, inValidEnroll: Boolean): Cipher
    {
        val cipher = getCipher()
        val secretKey =  getOrCreateSecretKey(keyName, inValidEnroll)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    public override fun getInitCipherForDecrypt(keyName: String, initializationVector: ByteArray): Cipher
    {
        val cipher = getCipher()
        val secretKey = getSecretKey(keyName) ?: throw Exception("Key does not exist")
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
        val prefs = context.getSharedPreferences(filename, mode)
        prefs.edit()
            .putString("${prefKey}_ciphertext", Base64.encodeToString(ciphertextWrapper.ciphertext, Base64.DEFAULT))
            .putString("${prefKey}_iv", Base64.encodeToString(ciphertextWrapper.initVector, Base64.DEFAULT))
            .apply()
    }

    public override fun getCiphertextWrapperFromSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ): CiphertextWrapper?
    {
        val prefs = context.getSharedPreferences(filename, mode)
        val ciphertextStr = prefs.getString("${prefKey}_ciphertext", null) ?: return null
        val ivStr = prefs.getString("${prefKey}_iv", null) ?: return null

        return try {
            val ciphertext = Base64.decode(ciphertextStr, Base64.DEFAULT)
            val iv = Base64.decode(ivStr, Base64.DEFAULT)
            CiphertextWrapper(ciphertext, iv)
        } catch (e: Exception) {
            null
        }
    }

    private fun getCipher(): Cipher {
        val transformation = "${Constants.ENCRYPTION_ALGORITHM}/${Constants.ENCRYPTION_BLOCK_MODE}/${Constants.ENCRYPTION_PADDING}"
        return Cipher.getInstance(transformation)
    }

    private  fun getSecretKey(keyName: String) : SecretKey? {
        val keyStore = KeyStore.getInstance(Constants.ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        return keyStore.getKey(keyName, null) as? SecretKey
    }

    private fun getOrCreateSecretKey(keyName: String, inValidEnroll : Boolean = true): SecretKey
    {
        // If SecretKey was previously created for that keyName, then grab and return it.

        val keyStore = KeyStore.getInstance(Constants.ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed

        val existingKey = getSecretKey(keyName)

        if(existingKey != null) {
            return try {
                val cipher = getCipher()
                cipher.init(Cipher.ENCRYPT_MODE, existingKey)
                existingKey
            } catch (e: Exception) {
                // Key invalid delete to create new one
                keyStore.deleteEntry(keyName)
                null
            } ?: createSecretKey(keyName, inValidEnroll)
        }

        // if key not exist create new one
        return createSecretKey(keyName, inValidEnroll)
    }

    private fun createSecretKey(keyName: String , inValidEnroll : Boolean = true): SecretKey {
        val keyGenParams = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(Constants.ENCRYPTION_BLOCK_MODE)
            .setEncryptionPaddings(Constants.ENCRYPTION_PADDING)
            .setKeySize(Constants.KEY_SIZE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(inValidEnroll)
            .build()

        val keyGenerator = KeyGenerator.getInstance(Constants.ENCRYPTION_ALGORITHM, Constants.ANDROID_KEYSTORE)
        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }

    public override fun getKeyState(keyName: String): Int {
        val secretKey = getSecretKey(keyName) ?: return KeyState.NonExist
        return try {
            val cipher = getCipher()
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            KeyState.Valid
        } catch (e: Exception) {
            KeyState.InValid
        }
    }
}

data class CiphertextWrapper(val ciphertext: ByteArray, val initVector: ByteArray)