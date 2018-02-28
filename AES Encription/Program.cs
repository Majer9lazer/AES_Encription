using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES_Encription
{
    class Program
    {
        static void Main(string[] args)

        {
            try
            {


              //  string original = "Спокойной Ночи))";
                string encriptedmessage = "";
                // Create a new instance of the Aes
                // class.  This generates a new key and initialization 
                // vector (IV).
                string encriptedmessage_ = @"177.202.29.195.143.157.71.155.100.237.238.219.78.52.3.86.127.199.67.250.37.45.137.120.41.101.197.135.153.116.9.150";
                string Key = "91.87.218.41.248.3.161.109.176.219.191.234.233.178.88.41.192.190.205.197.100.205.161.48.220.7.238.214.92.190.114.164";
                string IV = "104.15.161.126.187.213.109.192.72.223.205.21.55.199.186.235";
                var a_ = encriptedmessage_.Split('.');
                var b_ = Key.Split('.');
                var c_ = IV.Split('.');
                byte[] sub_a = new byte[a_.Length];
                for (int i = 0; i < a_.Length; i++)
                {
                    sub_a[i] =Convert.ToByte(a_[i]);
                }
                byte[] sub_b = new byte[b_.Length];
                byte[] sub_c = new byte[c_.Length];
                for (int i = 0; i < b_.Length; i++)
                {
                    sub_b[i] = Convert.ToByte(b_[i]);
                }

                for (int i = 0; i < c_.Length; i++)
                {
                    sub_c[i] = Convert.ToByte(c_[i]);
                }

                string msg = DecryptStringFromBytes_Aes(sub_a, sub_b, sub_c);
                Console.WriteLine(msg);
                Console.ReadLine();
                using (Aes myAes = Aes.Create())
                {

                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(original,myAes.Key, myAes.IV);
                   
                    foreach (byte b in encrypted)
                    {
                        encriptedmessage += b+".";
                    }

                    Console.WriteLine(encriptedmessage);
                    // Decrypt the bytes to a string.
                    string mKey = "";
                    foreach (byte b in myAes.Key)
                    {
                        mKey += b + ".";
                    }

                    string iv = "";
                    foreach (byte b in myAes.IV)
                    {
                        iv += b + ".";
                    }

                    //Console.WriteLine($" Mkey - {mKey}\n IV - {iv}");
                    using (StreamWriter str= new StreamWriter("1.txt"))
                    {
                        str.Write($"encriptedmessage - {encriptedmessage}\n Key - {mKey}\nIV - {iv}");
                       
                    }
                    string roundtrip = DecryptStringFromBytes_Aes(encrypted,myAes.Key, myAes.IV);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", original);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key,byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key,aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key
, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key
, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt
, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(
csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting 
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
    }
}

