# Pure Kotlin implementation of block ciphers
Kotlin program based on cryptography algorithms for encryption and decryption information using AES and DES.

## Requirements
- [JAVA 8+](https://www.java.com/en/download/)
- [GRADLE](https://docs.gradle.org/current/userguide/installation.html#installing_with_a_package_manager)

## Build project
    ➜  crypto-symmetric: gradle build
    ➜  ...
    ➜  crypto-symmetric: gradle jar

## Usage 

    usage: java -jar crypto-symmetric.jar [-b] -e|-d -c CIPHER -s FILE [-r FILE] -k KEY

```
optional arguments:
  -b         : specify binary output
  -d         : decrypt message
  -e         : encrypt message
  -k KEY     : secret key
  -s FILE    : source file
  -r FILE    : result file
  -c CIPHER  : AES or DES
```

## Examples
  #### DES
  - Encryption
    ```
    ➜  java -jar crypto-symmetric.jar -e -c DES -s src.txt -r res.txt -k "SuperKey"
    ```
  - Decryption
    ```
    ➜  java -jar crypto-symmetric.jar -d -c DES -s res.txt -r tmp.txt -k "SuperKey"
    ```
  #### AES
  - Encryption
    ```
    ➜  java -jar crypto-symmetric.jar -e -c AES -s src.txt -r res.txt -k "SuperSecretKey10"
    ```
  - Decryption
    ```
    ➜  java -jar crypto-symmetric.jar -d -c AES -s res.txt -r tmp.txt -k "SuperSecretKey10"
    ```
    
## TODO
- [ ] Translate all comments in the code into English

## License & copyright
Licensed under the [MIT-License](LICENSE.md).