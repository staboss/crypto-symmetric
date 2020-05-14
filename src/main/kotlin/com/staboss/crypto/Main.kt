package com.staboss.crypto

import com.staboss.crypto.cipher.aes.CipherAES
import com.staboss.crypto.cipher.des.CipherDES
import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.contains("-h") || args.isEmpty()) {
        Parser.usage()
        return
    }

    val parser = Parser.getInstance()
    if (!parser.parseArgs(args)) return

    val secretKey = parser.key
    val cipher = if (parser.cipher == "DES") CipherDES(secretKey) else CipherAES(secretKey)

    val result: String

    if (parser.encrypt) {
        var plainText = parser.message
        result = if (parser.cipher == "DES") {
            while (plainText.length % 8 != 0) plainText += ' '
            plainText.chunked(8).joinToString("") { cipher.encrypt(it, parser.binary) }
        } else {
            while (plainText.length % 16 != 0) plainText += ' '
            plainText.chunked(16).joinToString("") { cipher.encrypt(it, parser.binary) }
        }
    } else {
        val cipherText = parser.message
        result = if (parser.cipher == "DES") {
            if (cipherText.length % 8 != 0 || cipherText.length < 8) {
                System.err.println("The cipher text length for DES must be a multiple of 8, the current length: ${cipherText.length}")
                exitProcess(1)
            }
            cipherText.chunked(8).joinToString("") { cipher.decrypt(it, parser.binary) }
        } else {
            if (cipherText.length % 32 != 0 || cipherText.length < 32) {
                System.err.println("The cipher text (hex format) length for AES must be a multiple of 16 bytes, the current length: ${cipherText.length / 2}")
                exitProcess(1)
            }
            cipherText.chunked(32).joinToString("") { cipher.decrypt(it, parser.binary) }
        }
    }

    with(parser) {
        if (resultFile.isNullOrEmpty()) {
            val file = File(sourceFile)
            resultFile = file.absolutePath.substring(0, file.absolutePath.lastIndexOf('/')) + "/new_${file.name}"
        }
        File(resultFile).writeText(result.trim())
        println("The result was successfully saved to: \"${resultFile}\"")
    }
}
