package com.project5e.whisper

import javax.crypto.Mac
import javax.crypto.SecretKey


open class HOTP constructor(keySource: ByteArray, val digits: Int = 4, val algorithm: String = MAC_ALGORITHM) {

    private val key: SecretKey = keySource.toKey(MAC_ALGORITHM)

    private val modDivisor = when (digits) {
        4 -> 10000L
        5 -> 100000L
        6 -> 1000000L
        7 -> 10000000L
        8 -> 100000000L
        else -> throw IllegalArgumentException("digits length must be between 4 and 8 digits.")
    }

    fun apply(counter: Long): Int {
        val mac: Mac = Mac.getInstance(algorithm)
        mac.init(key)
        val buffer = mac.doFinal(counter.toBytes())
        val offset: Int = (buffer[buffer.size - 1] and 0x0f).toInt()
        return buffer.result(offset)
    }
    fun apply(counter: Int): Int = apply(counter.toLong())
    fun applyToString(counter: Int): String = apply(counter).toString(digits)
    fun applyToString(counter: Long): String = apply(counter).toString(digits)

    private fun ByteArray.result(offset: Int): Int {
        val intVal = this.sliceArray(offset until offset + 4).toInt()
        val uintVal = intVal.toLong() and 0xFFFF_FFFF
        return (uintVal % modDivisor).toInt()
    }

    companion object {
        const val MAC_ALGORITHM = "HmacSHA256"

        private fun Number.toString(digits: Int) = toString().padStart(digits, '0')
    }
}
