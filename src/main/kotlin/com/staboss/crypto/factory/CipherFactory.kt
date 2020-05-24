package com.staboss.crypto.factory

import com.staboss.crypto.cipher.Cipher
import com.staboss.crypto.cipher.CipherType
import com.staboss.crypto.cipher.aes.CipherAES
import com.staboss.crypto.cipher.des.CipherDES

object CipherFactory {
    fun create(cipherType: CipherType, key: String): Cipher = when (cipherType) {
        CipherType.AES -> CipherAES(key)
        CipherType.DES -> CipherDES(key)
    }

    fun getCipherType(type: String): CipherType? = when (type) {
        "DES" -> CipherType.DES
        "AES" -> CipherType.AES
        else -> null
    }
}