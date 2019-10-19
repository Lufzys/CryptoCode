using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace CryptoCode
{
    /**************************************************************************/
    /* Source -> http://www.kodkaynagi.com/c-kullanarak-sifreleme-yontemleri/ */
    /* Edit by Lufzys                                                         */
    /**************************************************************************/

    class CryptoCode
    {
        public static class Hash
        {
            #region MD5

            public static string MD5(string strGiris)
            {
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    MD5CryptoServiceProvider sifre = new MD5CryptoServiceProvider();
                    byte[] arySifre = Methods.StringToByte(strGiris);
                    byte[] aryHash = sifre.ComputeHash(arySifre);
                    return BitConverter.ToString(aryHash);
                }
            }

            #endregion

            #region SHA1

            public static string SHA1(string strGiris)
            {
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    SHA1CryptoServiceProvider sifre = new SHA1CryptoServiceProvider();
                    byte[] arySifre = Methods.StringToByte(strGiris);
                    byte[] aryHash = sifre.ComputeHash(arySifre);
                    return BitConverter.ToString(aryHash);
                }
            }

            #endregion

            #region SHA256

            public static string SHA256(string strGiris)
            {
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    SHA256Managed sifre = new SHA256Managed();
                    byte[] arySifre = Methods.StringToByte(strGiris);
                    byte[] aryHash = sifre.ComputeHash(arySifre);
                    return BitConverter.ToString(aryHash);
                }
            }

            #endregion

            #region SHA384

            public static string SHA384(string strGiris)
            {
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    SHA384Managed sifre = new SHA384Managed();
                    byte[] arySifre = Methods.StringToByte(strGiris);
                    byte[] aryHash = sifre.ComputeHash(arySifre);
                    return BitConverter.ToString(aryHash);
                }
            }

            #endregion

            #region SHA512

            public static string SHA512(string strGiris)
            {
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    SHA512Managed sifre = new SHA512Managed();
                    byte[] arySifre = Methods.StringToByte(strGiris);
                    byte[] aryHash = sifre.ComputeHash(arySifre);
                    return BitConverter.ToString(aryHash);
                }
            }

            #endregion
        }

        public static class Symmetric
        {
            #region DES // Requires 8 bit key
            public static string DESCrypt(string strGiris, string strKey = "15278596")
            {
                string sonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 8)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(8)); // 8 bit 
                        byte[] aryIV = Methods.Byte8(strKey.Substring(8)); // 8 bit 
                        DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                        MemoryStream ms = new MemoryStream();
                        CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                        StreamWriter writer = new StreamWriter(cs);
                        writer.Write(strGiris);
                        writer.Flush();
                        cs.FlushFinalBlock();
                        writer.Flush();
                        sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                        writer.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 8 letters!"); }
                }
                return sonuc;
            }

            public static string DESDecrypt(string strGiris, string strKey = "15278596")
            {
                string strSonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 8)
                    {
                        byte[] aryKey = Methods.Byte8(strKey); // 8 bit 
                        byte[] aryIV = Methods.Byte8(strKey); // 8 bit 
                        DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
                        MemoryStream ms = new MemoryStream(Convert.FromBase64String(strGiris));
                        CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                        StreamReader reader = new StreamReader(cs);
                        strSonuc = reader.ReadToEnd();
                        reader.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 8 letters!"); }
                }
                return strSonuc;
            }

            #endregion

            #region TripleDES // Requires 24 bit key

            public static string TripleDESCrypt(string strGiris, string strKey = "154875859854875154859658")
            {
                string sonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 24)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(24));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(8));
                        TripleDESCryptoServiceProvider dec = new TripleDESCryptoServiceProvider();
                        MemoryStream ms = new MemoryStream();
                        CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                        StreamWriter writer = new StreamWriter(cs);
                        writer.Write(strGiris);
                        writer.Flush();
                        cs.FlushFinalBlock();
                        writer.Flush();
                        sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                        writer.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 24 letters!"); }
                }
                return sonuc;
            }

            public static string TripleDESDecrypt(string strGiris, string strKey = "154875859854875154859658")
            {
                string strSonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if (strKey.Length == 24)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(24));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(8));
                        TripleDESCryptoServiceProvider cryptoProvider = new TripleDESCryptoServiceProvider();
                        MemoryStream ms = new MemoryStream(Convert.FromBase64String(strGiris));
                        CryptoStream cs = new CryptoStream(ms, cryptoProvider.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                        StreamReader reader = new StreamReader(cs);
                        strSonuc = reader.ReadToEnd();
                        reader.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 24 letters!"); }
                }
                return strSonuc;
            }

            #endregion

            #region RC2 // Requires 8 bit key

            public static string RC2Crypt(string strGiris, string strKey = "15278596")
            {
                string sonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 8)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(8));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(8));
                        RC2CryptoServiceProvider dec = new RC2CryptoServiceProvider();
                        MemoryStream ms = new MemoryStream();
                        CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                        StreamWriter writer = new StreamWriter(cs);
                        writer.Write(strGiris);
                        writer.Flush();
                        cs.FlushFinalBlock();
                        writer.Flush();
                        sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                        writer.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 8 letters!"); }
                }
                return sonuc;
            }

            public static string RC2Decrypt(string strGiris, string strKey = "15278596")
            {
                string strSonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 8)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(8));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(8));
                        RC2CryptoServiceProvider cp = new RC2CryptoServiceProvider();
                        MemoryStream ms = new MemoryStream(Convert.FromBase64String(strGiris));
                        CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                        StreamReader reader = new StreamReader(cs);
                        strSonuc = reader.ReadToEnd();
                        reader.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 8 letters!"); }
                }
                return strSonuc;
            }

            #endregion

            #region Rijndael // Requires 16 bit key

            public static string RijndaelCrypt(string strGiris, string strKey = "8362947383928374")
            {
                string sonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 16)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(8));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(16));
                        RijndaelManaged dec = new RijndaelManaged();
                        dec.Mode = CipherMode.CBC;
                        MemoryStream ms = new MemoryStream();
                        CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(aryKey, aryIV), CryptoStreamMode.Write);
                        StreamWriter writer = new StreamWriter(cs);
                        writer.Write(strGiris);
                        writer.Flush();
                        cs.FlushFinalBlock();
                        writer.Flush();
                        sonuc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                        writer.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 16 letters!"); }
                }
                return sonuc;
            }
            public static string RijndaelCoz(string strGiris, string strKey = "8362947383928374")
            {
                string strSonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    if(strKey.Length == 16)
                    {
                        byte[] aryKey = Methods.Byte8(strKey.Substring(8));
                        byte[] aryIV = Methods.Byte8(strKey.Substring(16));
                        RijndaelManaged cp = new RijndaelManaged();
                        MemoryStream ms = new MemoryStream(Convert.FromBase64String(strGiris));
                        CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(aryKey, aryIV), CryptoStreamMode.Read);
                        StreamReader reader = new StreamReader(cs);
                        strSonuc = reader.ReadToEnd();
                        reader.Dispose();
                        cs.Dispose();
                        ms.Dispose();
                    }
                    else { throw new ArgumentNullException("The key must be 16 letters!"); }
                }
                return strSonuc;
            }

            #endregion
        }

        public static class Asymmetric
        {
            #region RSA

            public static string RSACrypt(string strGiris, out RSAParameters prm)
            {
                string strSonuc = "";
                if (strGiris == "")
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    byte[] aryDizi = Methods.StringToByte(strGiris);
                    RSACryptoServiceProvider dec = new RSACryptoServiceProvider();
                    prm = dec.ExportParameters(true);
                    byte[] aryDonus = dec.Encrypt(aryDizi, false);
                    strSonuc = Convert.ToBase64String(aryDonus);
                }
                return strSonuc;
            }

            public static string RSADecrypt(string strGiris, RSAParameters prm)
            {
                string strSonuc = "";
                if (strGiris == "" || strGiris == null)
                {
                    throw new ArgumentNullException("No have any data!");
                }
                else
                {
                    RSACryptoServiceProvider dec = new RSACryptoServiceProvider();
                    byte[] aryDizi = Convert.FromBase64String(strGiris);
                    UnicodeEncoding UE = new UnicodeEncoding();
                    dec.ImportParameters(prm);
                    byte[] aryDonus = dec.Decrypt(aryDizi, false);
                    strSonuc = UE.GetString(aryDonus);
                }
                return strSonuc;
            }

            #endregion
        }

        public static class Methods
        {
            public static byte[] StringToByte(string deger)
            {
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                return ByteConverter.GetBytes(deger);
            }
            public static byte[] Byte8(string deger)
            {
                char[] arrayChar = deger.ToCharArray();
                byte[] arrayByte = new byte[arrayChar.Length];
                for (int i = 0; i < arrayByte.Length; i++)
                {
                    arrayByte[i] = Convert.ToByte(arrayChar[i]);
                }
                return arrayByte;
            }
        }
    }
}
