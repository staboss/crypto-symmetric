package com.staboss.crypto.cipher.des

import com.staboss.crypto.cipher.Cipher
import com.staboss.crypto.utils.*

class CipherDES(key: String) : Cipher(key) {

    private var c = IntArray(28)
    private var d = IntArray(28)

    private val roundKeys by lazy {
        val keys = Array(16) { IntArray(48) }
        for (round in 0 until 16) {
            keys[round] = generateRoundKey(round)
        }
        keys
    }

    init {
        if (keyBits.size != 64) {
            keyLengthError("DES", "128", "${keyBits.size}")
        }
    }

    override fun encrypt(plainText: String, isBinaryFormat: Boolean): String {
        val inputBits = plainText.toBinaryArray()
        val result = permute(inputBits, keyBits, false)

        return if (isBinaryFormat) result.joinToString("") else result.toText()
    }

    override fun decrypt(cipherText: String, isBinaryFormat: Boolean): String {
        val inputBits = cipherText.toBinaryArray()
        val result = permute(inputBits, keyBits, true).toText()

        return if (isBinaryFormat) result.toBinaryArray().joinToString("") else result
    }

    /**
     * Основаная функция шифрования и расшифрования сообщения
     *
     * @param inputBits последовательность битов сообщения
     * @param keyBits последовательность битов ключа
     * @param isDecrypt режим шифрования / расшифрования
     * @return результат шифрования / расшифрования
     */
    private fun permute(inputBits: IntArray, keyBits: IntArray, isDecrypt: Boolean): IntArray {
        // Первый шаг перестановки принимает входные биты и переставляет в массив newBits
        val newBits = inputBits.indices.map { inputBits[IP[it] - 1] }.toIntArray()

        // Массивы l и r создаются для хранения левой и правой половинок сообщения
        var lBlock = IntArray(32)
        var rBlock = IntArray(32)

        (0 until 28).forEach { i -> c[i] = keyBits[PC1[i] - 1] }
        (0 until 28).forEach { j -> d[j] = keyBits[PC1[j + 28] - 1] }

        System.arraycopy(newBits, 0, lBlock, 0, 32)
        System.arraycopy(newBits, 32, rBlock, 0, 32)

        var roundKey: IntArray
        for (n in 0 until 16) {
            roundKey = if (isDecrypt) roundKeys[15 - n] else roundKeys[n]
            val newR = fiestelFunc(rBlock, roundKey)
            val newL = lBlock xor newR
            lBlock = rBlock
            rBlock = newL
        }

        // Меняем местами левую и правую стороны
        val result = IntArray(64)
        System.arraycopy(rBlock, 0, result, 0, 32)
        System.arraycopy(lBlock, 0, result, 32, 32)

        // Применяем таблицу окончательной перестановки FP к полученному результату
        return (0 until 64).map { result[FP[it] - 1] }.toIntArray()
    }

    /**
     * Функция Фейстеля
     *
     * @param rBlock правая часть бинарной последовательности
     * @param roundKey раундовый ключ
     * @return результат алгоритма Фейстеля
     */
    private fun fiestelFunc(rBlock: IntArray, roundKey: IntArray): IntArray {
        // Сначала 32 бита массива rBlock расширяются с использованием таблицы расширения E до 48 бита
        val expandedR = (0 until 48).map { rBlock[E[it] - 1] }.toIntArray()

        // Операция XOR между расширенным блоком и раундовым ключом
        val temp = expandedR xor roundKey

        // Затем к результату операции XOR применяются S-блоки
        return sBlock(temp)
    }

    /**
     * Применение S-блоков (блоков замены)
     *
     * @param bits бинарная последовательность
     * @return результат одного раунда S-блока
     */
    private fun sBlock(bits: IntArray): IntArray {
        val result = IntArray(32)

        for (i in 0 until 8) {
            // 0 и 5 биты дают биты номера строки
            val row = "${bits[6 * i]}${bits[6 * i + 5]}"

            // с 1 по 4 биты дают биты номера столбца
            val col = buildString {
                (1..4).forEach { bitIndex ->
                    append(bits[6 * i + bitIndex])
                }
            }

            val r = row.toInt(radix = 2)
            val c = col.toInt(radix = 2)

            // Десятичное значение S-блока
            val x = S[i][r * 16 + c].toInt()

            var s = Integer.toBinaryString(x)
            while (s.length < 4) s = "0$s"

            // Биты добавляются к результирующему значению
            for (j in 0 until 4) {
                result[i * 4 + j] = s[j].toString().toInt()
            }
        }

        // Применение таблицы перестановок к полученному значению
        return (0 until 32).map { result[P[it] - 1] }.toIntArray()
    }

    /**
     * Функция генерации раундового ключа
     *
     * @param round номер раунда
     * @return раундовый ключ
     */
    private fun generateRoundKey(round: Int): IntArray {
        val shiftTimes = shifts[round].toInt()

        // c1 и d1 - новые значения c и d, которые будут сгенерированы в этом раунде
        val c1 = c leftShift shiftTimes
        val d1 = d leftShift shiftTimes

        // c1d1 хранит вместе половинки c1 и d1
        val c1d1 = IntArray(56)
        System.arraycopy(c1, 0, c1d1, 0, 28)
        System.arraycopy(d1, 0, c1d1, 28, 28)

        // k хранит подключ, который генерируется путем применения таблицы итоговой перестановки ключа PC2 к c1d1
        val k = IntArray(48).apply {
            indices.forEach { i ->
                this[i] = c1d1[PC2[i] - 1]
            }
        }

        c = c1; d = d1
        return k
    }
}
