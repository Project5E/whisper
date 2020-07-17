package com.project5e.whisper

import java.lang.IllegalArgumentException
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

open class HKDF(keySource: ByteArray, private val keySize: Int = 256) {
    private val secretKey = SecretKeySpec(keySource, MAC_ALGORITHM)

    private val mac = Mac.getInstance(MAC_ALGORITHM)
        .apply { init(keySource.toKey(MAC_ALGORITHM)) }

    fun apply(input: ByteArray): ByteArray = apply(input, keySize, secretKey, mac)

    companion object {
        private const val MAC_ALGORITHM = "HmacSHA256"

        @JvmStatic
        fun apply(
            input: ByteArray,
            keySize: Int = 256,
            secretKey: SecretKey? = null,
            mac: Mac? = null
        ): ByteArray {
            if (secretKey == null && mac == null) throw IllegalArgumentException()
            val instance = mac ?: Mac.getInstance(MAC_ALGORITHM).apply { init(secretKey) }
            return instance.doFinal(input).sliceArray(0 until keySize / 8)
        }

        @JvmStatic
        fun apply(
            input: ByteArray,
            keySize: Int = 256,
            secretKey: ByteArray? = null,
            mac: Mac? = null
        ): ByteArray =
            apply(input, keySize, secretKey?.toKey(MAC_ALGORITHM), mac)

    }
}