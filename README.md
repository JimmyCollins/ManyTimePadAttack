# Many Time Pad Attack

### MSc. Software Development - Applied Cryptography Assignment 1

#### Description

>>>The purpose here is to see what goes wrong when a stream cipher key is used more than once.

>>>Below are 16 hex-encoded ciphertexts that are the result of encrypting 16 plaintexts with a stream cipher One Time Pad, all with the same stream cipher key. i.e. the result of XORing the plaintexts with the same key, which was as long as the longest plaintext message. Your goal is to decrypt the last ciphertext.

>>>For simplicity, and to aid the learning process, all of the plaintexts consist of lower-case letters and spaces only. There are no upper-case letters or punctuations.

#### Development Environment

 - Language: C#
 - Runtime: .NET 4.5
 - IDE: Visual Studio Professional 2012

#### Files

 - Program.cs – the main logic of the program.
 - Cipertexts.xml – an XML file from where the given ciphertexts are read.
 - DecryptionKey.cs – a simple object representing a decryption key.

#### Execution (Windows only)

 - The compiled program (“Question1.exe”) is run from the command line.
