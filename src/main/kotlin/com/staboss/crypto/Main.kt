package com.staboss.crypto

import com.staboss.crypto.cipher.CipherType
import com.staboss.crypto.factory.CipherFactory
import java.io.File
import java.lang.System.err
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.contains("-h") || args.isEmpty()) {
        Parser.usage()
        return
    }

    val factory = CipherFactory
    val parser = Parser.getInstance()

    if (!parser.parseArgs(args)) return

    val cipherType = factory.getCipherType(parser.cipher) ?: error("Invalid cipher type")
    val cipherMode = factory.create(cipherType, parser.key)

    val alphaHex by lazy {
        if (cipherType == CipherType.AES) 2 else 1
    }

    val result: String

    if (parser.encrypt) {
        var plainText = parser.message

        while (plainText.length % cipherType.blockLength != 0) {
            plainText += ' '
        }

        result = plainText.chunked(cipherType.blockLength).joinToString("") {
            cipherMode.encrypt(it, parser.binary)
        }
    } else {
        val cipherText = parser.message
        val blockLength = cipherType.blockLength * alphaHex

        if (cipherText.length % blockLength != 0 || cipherText.length < blockLength) {
            textErrorMessage(cipherType, cipherText.length)
        }

        result = cipherText.chunked(blockLength).joinToString("") {
            cipherMode.decrypt(it, parser.binary)
        }
    }

    with(parser) {
        if (resultFile.isNullOrEmpty()) {
            val file = File(sourceFile)
            resultFile = file.absolutePath.substring(0, file.absolutePath.lastIndexOf('/')) + "/new_${file.name}"
        }
        File(resultFile).apply {
            writeText(result.trim())
            println("The result was successfully saved to: \"${absolutePath}\"")
        }
    }
}

fun textErrorMessage(cipherType: CipherType, length: Int): Nothing {
    val temp = if (cipherType == CipherType.AES) "(hex format) length for AES" else "length for DES"
    err.println("The cipher text $temp must be a multiple of ${cipherType.blockLength}, the current length: $length")
    exitProcess(1)
}