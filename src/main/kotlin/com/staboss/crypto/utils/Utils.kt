package com.staboss.crypto.utils

import kotlin.system.exitProcess

/**
 * Преобразует символ в его шестнадцатеричный формат
 *
 * @return шестнадцатеричное представление символа
 */
fun Char.toInt16(): Int = Integer.valueOf(toInt().toString(), 10)

/**
 * Преобразует символ в его двоичный формат
 *
 * @param bits кодировка
 * @return двоичное представление символа
 */
fun Char.toBinary(bits: Int = 8): String {
    val temp = toInt().toString(radix = 2)
    return if (temp.length != bits) "0".repeat(bits - temp.length) + temp else temp
}

/**
 * Преобразует число в его двоичный формат
 *
 * @param bits кодировка
 * @return двоичное представление числа
 */
fun Int.toBinary(bits: Int = 8): String {
    val temp = toString(radix = 2)
    return if (temp.length != bits) "0".repeat(bits - temp.length) + temp else temp
}

/**
 * Преобразует строку в двоичное представление
 *
 * @param bits кодировка
 * @return массив битов
 */
fun String.toBinaryArray(bits: Int = 8): IntArray =
        map { char -> char.toBinary(bits) }
                .flatMap { binaryString -> binaryString.toList() }
                .map { bit -> bit.toString().toInt() }
                .toIntArray()

/**
 * Преобразует массив битов в текст
 *
 * @param bits кодировка
 * @return текст
 */
fun IntArray.toText(bits: Int = 8): String =
        joinToString(separator = "") { bit -> bit.toString() }
                .chunked(bits)
                .map { binaryString -> binaryString.toInt(radix = 2).toChar() }
                .joinToString(separator = "")

/**
 * Исключающее или (XOR) двух массивов поэлементно
 *
 * @param x второй массив
 * @return новый массив
 */
infix fun IntArray.xor(x: IntArray): IntArray = indices.map { this[it] xor x[it] }.toIntArray()

/**
 * Операция побитогого сдвига массива влево на n элементов
 *
 * @param n количество сдвигов
 * @return новый массив
 */
infix fun IntArray.leftShift(n: Int): IntArray {
    val res = IntArray(size)
    System.arraycopy(this, 0, res, 0, size)

    repeat(n) {
        val tmp = res[0]
        for (i in 1 until size) res[i - 1] = res[i]
        res[lastIndex] = tmp
    }

    return res
}

/**
 * Ошибка ввода ключа
 *
 * @param mode стандарт шифрования
 * @param required требуемая длина ключа
 * @param current фактическая длина ключа
 */
fun keyLengthError(mode: String, required: String, current: String): Nothing {
    System.err.println("The key length for $mode must be $required bits, the current key length: $current")
    exitProcess(1)
}
