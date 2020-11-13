package com.project5e.whisper

import java.nio.Buffer
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

private val b62 = Base62.createInstance()
private val b64Enc = Base64.getEncoder()
private val b64Dec = Base64.getDecoder()
private val sha256 = MessageDigest.getInstance("SHA-256")

infix fun Int.`**`(exponent: Int): Int = toDouble().pow(exponent).toInt()
infix fun Byte.and(other: Int): Byte = (toInt() and other).toByte()
infix fun Byte.or(other: Byte): Byte = (toInt() or other.toInt()).toByte()
infix fun Byte.shl(other: Int): Byte = (toInt() shl other).toByte()

fun Long.toBytes(): ByteArray {
  val buffer: ByteBuffer = ByteBuffer.allocate(java.lang.Long.BYTES)
  buffer.putLong(this)
  return buffer.array()
}

fun ByteArray.toLong(): Long {
  val buffer: ByteBuffer = ByteBuffer.allocate(java.lang.Long.BYTES)
  buffer.put(this)
  (buffer as Buffer).flip() // need flip
  return buffer.long
}

fun ByteArray.toInt(): Int {
  val buffer: ByteBuffer = ByteBuffer.allocate(Integer.BYTES)
  buffer.put(this)
  buffer.flip() // need flip
  return buffer.int
}

fun ByteArray.toBase62(): String = b62.encode(this)
fun ByteArray.toBase64(): String = b64Enc.encodeToString(this)
val ByteArray.hex: String
  get() = joinToString("") { (it.toInt() and 0xFF).toString(16) }


fun String.fromBase62(): ByteArray = b62.decode(this)
fun String.fromBase64(): ByteArray = b64Dec.decode(this)

fun ByteArray.toKey(algorithm: String): SecretKey = SecretKeySpec(this, algorithm)
@Synchronized
fun ByteArray.sha256(): ByteArray = sha256.digest(this)