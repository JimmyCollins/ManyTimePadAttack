/****************************************************************************************
 * COMP9012 - Applied Cryptography
 * Assignment 1
 * 
 * Name:                Jimmy Collins
 * Email:               jimmy.collins@mycit.ie
 * Student Number:      R00145569
 * 
 * Creation Date:       Saturday, March 3rd 2018
 * 
 * **************************************************************************************/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace Question1
{
    class Program
    {
        static List<string> CipherTexts;                 // List of Ciphertexts to decrypt (read from XML)
        static List<DecryptionKey> DecryptionKeys;      // List of decryption keys per position (built up along the way)

        static void Main(string[] args)
        {
            // Read the given ciphertexts from the XML file where I store them
            CipherTexts = ReadCipherTexts();
            DecryptionKeys = new List<DecryptionKey>();

            Console.WriteLine("Read {0} ciphertexts from XML.", CipherTexts.Count);

            int currentCipherIndex = 0;

            // Iterating over Ciphers as Hex Strings
            while (currentCipherIndex < CipherTexts.Count)
            {
                Console.WriteLine("Current Cipher Index: " + currentCipherIndex);

                byte[] currentCipherAsBytes = StringToByteArray(CipherTexts[currentCipherIndex]);

                int currentByteIndex = 0;

                // Iterating over Bytes in the current Cipher
                while (currentByteIndex < currentCipherAsBytes.Length)
                {
                    Console.WriteLine("Checking Index: " + currentByteIndex);

                    // Get the current byte
                    byte currentByteValue = (byte)currentCipherAsBytes.GetValue(currentByteIndex);

                    // XOR this byte with the corresponding byte in each ciphertext (until we find a potential key)
                    for (int i = currentCipherIndex + 1; i < CipherTexts.Count; i++)
                    {
                        byte[] cipherAsBytes = StringToByteArray(CipherTexts[i]);

                        byte byteToXorAgainst;

                        try
                        {
                            byteToXorAgainst = cipherAsBytes[currentByteIndex];
                        }
                        catch
                        {
                            // No correspdonging byte at this location in this cipher (e.g. cipher could be shorter than the current one)
                            continue;
                        }

                        // XOR
                        int xor = currentByteValue ^ byteToXorAgainst;

                        // Check if we got an uppercase ASCII character
                        if (IsUpperCaseAscii(xor))
                        {
                            Console.WriteLine("XOR of current check (" + xor + ") is an uppercase ASCII character, value is: " + Convert.ToChar(xor));

                            // This means that one of the plain text characters is a space and one is the lowercase ASCII equivalent of this character

                            // We need to XOR each potential key with an ASCII space
                            int potentialKey1 = currentByteValue ^ 32;
                            int potentialKey2 = byteToXorAgainst ^ 32;

                            // These are our pontetial keys
                            Console.WriteLine("Potential Key 1 - " + potentialKey1);
                            Console.WriteLine("Potential Key 2 - " + potentialKey2);

                            // Check one of these keys is valid - if one isn't we'll assume the other is
                            Console.WriteLine("Checking Potential Key - " + potentialKey1);

                            if (CheckPotentialKey(potentialKey1, currentByteIndex))
                            {
                                Console.WriteLine("Key is valid - " + potentialKey1);

                                DecryptionKey key = new DecryptionKey();
                                key.Key = potentialKey1;
                                key.Position = currentByteIndex;
                                DecryptionKeys.Add(key);
                            }
                            else
                            {
                                Console.WriteLine("Key '" + potentialKey1 + "' not valid, assuming key '" + potentialKey2 + "' is valid");

                                DecryptionKey key = new DecryptionKey();
                                key.Key = potentialKey2;
                                key.Position = currentByteIndex;
                                DecryptionKeys.Add(key);
                            }

                            // Break out of checking further bytes at this position as we've found a valid key
                            break;

                        }
                    }

                    currentByteIndex++;
                }

                currentCipherIndex++;
            }

            // Decrypt the Ciphertexts
            Console.WriteLine("Now to decrypt the ciphertexts...");

            for (int i = 0; i < CipherTexts.Count; i++)
            {
                string decryptedCipher = DecryptCipherText(CipherTexts[i]);
                Console.WriteLine("Decrypted Ciphertext at Position '" + i + "' - " + decryptedCipher);
            }

        }


        /// <summary>
        /// Decrypt the given ciphertext using the pre-set list of decryption keys
        /// Assumes the list of decryption keys has been populated already
        /// </summary>
        static string DecryptCipherText(string cipherAsHex)
        {
            if (DecryptionKeys.Count == 0)
            {
                Console.WriteLine("ERROR: We don't seem to have a list of encryption keys.");
                return "ERROR";
            }

            string decryptedCipher = string.Empty;

            byte[] cipherAsBytes = StringToByteArray(cipherAsHex);

            // Iterate over the give cipher text and decrypt
            for (int i = 0; i < cipherAsBytes.Length; i++)
            { 

                // Find the decrytion key for this position
                DecryptionKey key = FindDecryptionKey(i);

                if (key == null)
                {
                    // We don't have a key for this position somehow - output ? instead
                    decryptedCipher += "?";
                    continue;
                }

                int xorResult = cipherAsBytes[i] ^ key.Key;

                // Convert to ASCII character
                char decryptedChar = Convert.ToChar(xorResult);

                decryptedCipher += decryptedChar;
            }

            return decryptedCipher;
        }


        /// <summary>
        /// Return the decryption key for the given position
        /// </summary>
        static DecryptionKey FindDecryptionKey(int position)
        {
            foreach (DecryptionKey key in DecryptionKeys)
            {
                if (key.Position == position)
                    return key;
            }

            return null;
        }


        /// <summary>
        /// Checks if the given key can be used to decrypt all values at the given position
        /// If the result of the XOR is a lowercase ASCII character, or a space, then this key is valid
        /// </summary>
        static bool CheckPotentialKey(int potentialKey, int position)
        {
            // For the given position, check if the given key will decrypt the value at that position by XOR'ing with the given potential key
            int currentCipherIndex = 0;

            // Assume this key is good until we find out otherwise
            bool keyIsGood = true;

            // Iterating over Ciphers as Hex Strings
            while (currentCipherIndex < CipherTexts.Count)
            {
                byte[] currentCipherAsBytes = StringToByteArray(CipherTexts[currentCipherIndex]);

                int byteToXorAgainst;
                try
                {
                    byteToXorAgainst = currentCipherAsBytes[position];
                }
                catch
                {
                    // No corresponding byte at this location in this cipher (e.g. cipher could be shorter than the current one)
                    currentCipherIndex++;
                    continue;
                }

                // XOR against potential key
                int xorResult = byteToXorAgainst ^ potentialKey;

                // Check if it's NOT a lowercase ASCII character or a space
                if(!IsLowerCaseAsciiOrSpace(xorResult))
                {
                    keyIsGood = false;
                }

                currentCipherIndex++;
            }

            return keyIsGood;
        }


        /// <summary>
        /// Convert a hexidecimal string to a byte array
        /// </summary>
        static byte[] StringToByteArray(string hex)
        {
            // LINQ is a bit inefficient here, but it will suffice for this purpose
            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }


        /// <summary>
        /// Determine if the given value is a uppercase ASCII character
        /// </summary>
        static bool IsUpperCaseAscii(int value)
        {
            if (value >= 65 && value <= 90)
            {
                return true; // Uppercase ASCII
            }

            return false;
        }


        /// <summary>
        /// Determine if the given value is a lowercase ASCII character or a space
        /// </summary>
        static bool IsLowerCaseAsciiOrSpace(int value)
        {
            if (value == 32)
                return true; // Space

            if (value >= 97 && value <= 122)
            {
                return true; // Lowercase ASCII
            }

            return false;
        }


        /// <summary>
        /// Reads the (hex encoded) ciphertexts from the XML where I store them
        /// </summary>
        static List<string> ReadCipherTexts()
        {
            List<string> ciphers = new List<string>();

            string docPath = "ciphertexts.xml";

            XmlDocument doc = new XmlDocument();
            doc.Load(docPath);

            XmlNodeList ciphertTextNodes = doc.GetElementsByTagName("ciphertext");

            foreach (XmlNode ciphertTextNode in ciphertTextNodes)
            {
                string cipher = ciphertTextNode.InnerText;
                ciphers.Add(cipher);
            }

            return ciphers;
        }

    }
}