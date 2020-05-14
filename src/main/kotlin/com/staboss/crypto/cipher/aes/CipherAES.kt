@file:Suppress("SameParameterValue")

package com.staboss.crypto.cipher.aes

import com.staboss.crypto.cipher.Cipher
import com.staboss.crypto.utils.keyLengthError
import com.staboss.crypto.utils.toBinary
import com.staboss.crypto.utils.toInt16

class CipherAES(key: String) : Cipher(key) {

    private val keyColumns: Int = when (keyBits.size) {
        128 -> 4
        192 -> 6
        256 -> 8
        else -> keyLengthError("AES", "128/192/256", "${keyBits.size}")
    }

    private val blockColumns = 4
    private val rounds = numrounds[keyColumns - 4][blockColumns - 4]

    private val secretKey = Array(4) { IntArray(MAX_KEY_COLUMNS) }
    private val roundKeys = Array(MAX_ROUNDS + 1) { Array(4) { IntArray(MAX_KEY_COLUMNS) } }

    init {
        var counter = 0
        matrixColumnLoop(keyColumns, 4) { i, j ->
            secretKey[i][j] = key[counter++].toInt16()
        }
        keyExpansion(secretKey, roundKeys)
    }

    override fun encrypt(plainText: String, isBinaryFormat: Boolean): String {
        val block = Array(4) { IntArray(MAX_BLOCK_COLUMNS) }

        var counter = 0
        matrixColumnLoop(blockColumns, 4) { i, j ->
            block[i][j] = plainText[counter++].toInt16()
        }

        encryptBlock(block, roundKeys)
        return buildString {
            matrixColumnLoop(blockColumns, 4) { i, j ->
                if (isBinaryFormat) append(block[i][j].toBinary())
                else append(String.format("%02X", block[i][j]))
            }
        }
    }

    override fun decrypt(cipherText: String, isBinaryFormat: Boolean): String {
        val block = Array(4) { IntArray(MAX_BLOCK_COLUMNS) }
        val hex16 = cipherText.chunked(2)

        var counter = 0
        matrixColumnLoop(blockColumns, 4) { i, j ->
            block[i][j] = hex16[counter++].toInt(radix = 16)
        }

        decryptBlock(block, roundKeys)
        return buildString {
            matrixColumnLoop(blockColumns, 4) { i, j ->
                if (isBinaryFormat) append(block[i][j].toBinary())
                else append(block[i][j].toChar())
            }
        }
    }

    /**
     *  Процедура шифрования [encryptBlock]
     *
     *  @param block блок текста, который представлен как прямоугольный массив байтов
     *  @param roundKeys массив раундовых ключей
     */
    private fun encryptBlock(block: Array<IntArray>, roundKeys: Array<Array<IntArray>>) {
        addRoundKey(block, roundKeys[0])

        for (round in 1 until rounds) {
            subBytes(block, S)
            shiftRows(block, 0)
            mixColumns(block)
            addRoundKey(block, roundKeys[round])
        }

        subBytes(block, S)
        shiftRows(block, 0)
        addRoundKey(block, roundKeys[rounds])
    }

    /**
     *  Процедура расшифрования [decryptBlock] (обратная процедуре шифрования)
     *
     *  @param block блок шифротекста, который представлен как прямоугольный массив байтов
     *  @param roundKeys массив раундовых ключей
     */
    private fun decryptBlock(block: Array<IntArray>, roundKeys: Array<Array<IntArray>>) {
        addRoundKey(block, roundKeys[rounds])
        shiftRows(block, 1)
        subBytes(block, Si)

        for (round in rounds - 1 downTo 1) {
            addRoundKey(block, roundKeys[round])
            invMixColumns(block)
            shiftRows(block, 1)
            subBytes(block, Si)
        }

        addRoundKey(block, roundKeys[0])
    }

    /**
     * Умножение первого множителя на [x] в поле GF(256)
     *
     * @param x второй множитель
     * @return результат умножения
     */
    private infix fun Int.mul(x: Int): Int = when {
        this != 0 && x != 0 -> ALOGTABLE[(LOGTABLE[this] + LOGTABLE[x]) % 255]
        else -> 0
    }

    /**
     * В процедуре [addRoundKey] каждый байт состояния [state] объединяется с [roundKey], используя операцию XOR
     *
     * @param state промежуточный результат, который представлен как прямоугольный массив байтов
     * @param roundKey раундовый ключ, который представлен как прямоугольный массив байтов
     */
    private fun addRoundKey(state: Array<IntArray>, roundKey: Array<IntArray>) =
            matrixRowLoop(4, blockColumns) { i, j ->
                state[i][j] = state[i][j] xor roundKey[i][j]
            }

    /**
     * В процедуре [subBytes] каждый байт в [state] заменяется соответствующим элементом
     * в фиксированной 8-битной таблице поиска [S] или [Si], где state(i, j) = S(state(i, j))
     *
     * @param state промежуточный результат, который представлен как прямоугольный массив байтов
     * @param sBox нелинейная таблица замен
     */
    private fun subBytes(state: Array<IntArray>, sBox: IntArray) =
            matrixRowLoop(4, blockColumns) { i, j ->
                state[i][j] = sBox[state[i][j]]
            }

    /**
     * В процедуре [shiftRows] байты в каждой строке [state] циклически сдвигаются влево,
     * а размер смещения байтов каждой строки зависит от её номера и размера ключа
     *
     * @param state промежуточный результат, который представлен как прямоугольный массив байтов
     * @param mode принмает 0 и 1, где 0 - шифрование, а 1 - расшифрование
     */
    private fun shiftRows(state: Array<IntArray>, mode: Int) {
        val tmp = IntArray(MAX_BLOCK_COLUMNS)
        for (i in 1 until 4) {
            var k: Int
            for (j in 0 until blockColumns) {
                k = if (mode == 0) {
                    (j + shifts[blockColumns - 4][i]) % blockColumns
                } else {
                    (blockColumns + j - shifts[blockColumns - 4][i]) % blockColumns
                }
                tmp[j] = state[i][k]
            }

            for (j in 0 until blockColumns) {
                state[i][j] = tmp[j]
            }
        }
    }

    /**
     * В процедуре [mixColumns] каждая колонка состояния [state] перемножается
     * с фиксированным многочленом c(x) в поле GF(256) по модулю n(x), где
     * - c(x) = 3⋅x³ + x² + x + 2
     * - n(x) = x⁴ + 1
     *
     * @param state промежуточный результат, который представлен как прямоугольный массив байтов
     */
    private fun mixColumns(state: Array<IntArray>) {
        val tmp = Array(4) { IntArray(MAX_BLOCK_COLUMNS) }

        matrixColumnLoop(blockColumns, 4) { i, j ->
            val mul1 = 2 mul state[i][j]
            val mul2 = 3 mul state[(i + 1) % 4][j]
            val mul3 = state[(i + 2) % 4][j]
            val mul4 = state[(i + 3) % 4][j]
            tmp[i][j] = mul1 xor mul2 xor mul3 xor mul4
        }

        matrixRowLoop(4, blockColumns) { i, j ->
            state[i][j] = tmp[i][j]
        }
    }

    /**
     * Процедура [invMixColumns] является обратной по отношению к [mixColumns]
     *
     * @param state промежуточный результат, который представлен как прямоугольный массив байтов
     */
    private fun invMixColumns(state: Array<IntArray>) {
        val tmp = Array(4) { IntArray(MAX_BLOCK_COLUMNS) }

        matrixColumnLoop(blockColumns, 4) { i, j ->
            val mul1 = 0xe mul state[i][j]
            val mul2 = 0xb mul state[(i + 1) % 4][j]
            val mul3 = 0xd mul state[(i + 2) % 4][j]
            val mul4 = 0x9 mul state[(i + 3) % 4][j]
            tmp[i][j] = mul1 xor mul2 xor mul3 xor mul4
        }

        matrixRowLoop(4, blockColumns) { i, j ->
            state[i][j] = tmp[i][j]
        }
    }

    /**
     * Процедура генерации раундовых ключей
     *
     * @param secretKey первичный ключ
     * @param roundKeys массив раундовых ключей
     */
    private fun keyExpansion(secretKey: Array<IntArray>, roundKeys: Array<Array<IntArray>>) {
        var tPointer = 0
        var rPointer = 1

        val tempKey = Array(4) { IntArray(MAX_KEY_COLUMNS) }.apply {
            matrixColumnLoop(keyColumns, 4) { i, j ->
                this[i][j] = secretKey[i][j]
            }
        }

        // Копирование в массив раундовых ключей
        fun copyValues() {
            var pointer = 0
            while ((pointer < keyColumns) && (tPointer < (rounds + 1) * blockColumns)) {
                for (i in 0 until 4) {
                    roundKeys[tPointer / blockColumns][i][tPointer % blockColumns] = tempKey[i][pointer]
                }
                pointer++; tPointer++
            }
        }

        copyValues()

        // Пока не рассчитано достаточное количество раундовых ключей
        while (tPointer < (rounds + 1) * blockColumns) {
            for (i in 0 until 4) {
                tempKey[i][0] = tempKey[i][0] xor S[tempKey[(i + 1) % 4][keyColumns - 1]]
            }
            tempKey[0][0] = tempKey[0][0] xor RC[rPointer++]

            when {
                keyColumns <= 6 -> {
                    for (j in 1 until keyColumns) {
                        for (i in 0 until 4) {
                            tempKey[i][j] = tempKey[i][j] xor tempKey[i][j - 1]
                        }
                    }
                }
                else -> {
                    for (j in 1 until 4) {
                        for (i in 0 until 4) {
                            tempKey[i][j] = tempKey[i][j] xor tempKey[i][j - 1]
                        }
                    }
                    for (i in 0 until 4) {
                        tempKey[i][4] = tempKey[i][4] xor S[tempKey[i][3]]
                    }
                    for (j in 5 until keyColumns) {
                        for (i in 0 until 4) {
                            tempKey[i][j] = tempKey[i][j] xor tempKey[i][j - 1]
                        }
                    }
                }
            }
            copyValues()
        }
    }

    /**
     * Цикл по строкам прямоугольного массива байтов
     *
     * @param firstRange промежуток основного цикла
     * @param secondRange промежуток вложенного цикла
     * @param task лямбда-выражение
     */
    private inline fun matrixRowLoop(firstRange: Int, secondRange: Int, task: (Int, Int) -> Unit) {
        for (i in 0 until firstRange) {
            for (j in 0 until secondRange) {
                task(i, j)
            }
        }
    }

    /**
     * Цикл по столбцам прямоугольного массива байтов
     *
     * @param firstRange промежуток основного цикла
     * @param secondRange промежуток вложенного цикла
     * @param task лямбда-выражение
     */
    private inline fun matrixColumnLoop(firstRange: Int, secondRange: Int, task: (Int, Int) -> Unit) {
        for (j in 0 until firstRange) {
            for (i in 0 until secondRange) {
                task(i, j)
            }
        }
    }
}
