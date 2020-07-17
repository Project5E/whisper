package com.project5e.whisper

import java.security.SecureRandom

object SecureRandomFactory {

    private val os = System.getProperty("os.name").toUpperCase()
    val DEFAULT: String = when {
        os.contains("WIN") -> "Windows-PRNG"
        else -> "NativePRNGNonBlocking"
    }

    val instance: SecureRandom
        get() = SecureRandom.getInstance(DEFAULT)
}