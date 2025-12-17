package com.vegeta.biometrics

interface UnityBiometricCallback {
    fun onSuccess(data: String)
    fun onFailure(error: String)
}