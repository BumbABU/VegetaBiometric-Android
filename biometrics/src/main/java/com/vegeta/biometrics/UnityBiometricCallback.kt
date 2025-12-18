package com.vegeta.biometrics

interface UnityBiometricCallback {
    fun onSuccess(data: String)
    fun onFailure(errCode: Int, errString: String)
}