package com.staboss.crypto.cipher

import com.staboss.crypto.utils.toBinaryArray

abstract class Cipher(key: String) {
    protected val keyBits: IntArray = key.toBinaryArray()

    abstract fun encrypt(plainText: String, isBinaryFormat: Boolean = false): String

    abstract fun decrypt(cipherText: String, isBinaryFormat: Boolean = false): String
}

enum class CipherType(val blockLength: Int) {
    AES(16), DES(8)
}
