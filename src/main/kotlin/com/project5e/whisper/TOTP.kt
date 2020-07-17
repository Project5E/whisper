package com.project5e.whisper

import java.time.Duration
import java.time.Instant

open class TOTP(keySource: ByteArray,
                val epoch: Instant = Instant.EPOCH,
                val step: Int = 30,
                digits: Int = 4,
                algorithm: String = MAC_ALGORITHM) : HOTP(keySource, digits, algorithm) {

    fun get(instant: Instant): Int {
        val counter = Duration.between(epoch, instant).seconds / step
        return apply(counter)
    }
    fun getString(instant: Instant): String = get(instant).toFixString(digits)

    fun now(): Int = get(Instant.now())
    fun prev(): Int = get(Instant.now().minusSeconds(step.toLong()))
    fun next(): Int = get(Instant.now().plusSeconds(step.toLong()))

    fun nowString(): String = now().toFixString(digits)
    fun prevString(): String = prev().toFixString(digits)
    fun nextString(): String = next().toFixString(digits)

    fun validate(challenge: String): Boolean {
        List(3) {
            getString(Instant.now().minusSeconds(step.toLong() * it))
        }.forEach {
            if (challenge == it) return true
        }
        return false
    }
}
