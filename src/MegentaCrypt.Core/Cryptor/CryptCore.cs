using MegentaCrypt.Core.Algorithms;
using MegentaCrypt.Core.CryptParams;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MagentaCrypt
{
    public class CryptCore
    {
        ICryptoAlgorithm _algorithm;
        KeyCrypt _key;
        IVCrypt _iv;
        public KeyCrypt Key
        {
            get { return _key; }
        }
        public IVCrypt IV
        {
            get { return _iv; }
        }
        string algorithmName;
        public CryptCore(KeyCrypt key, IVCrypt iv, CryptAlgorithm algorithm, ICryptoAlgorithm CustomAlgorithm = null)
        {
            _key = key;
            _iv = iv;
            algorithmName = Enum.GetName(typeof(CryptAlgorithm), algorithm);
            switch (algorithm)
            {
                case CryptAlgorithm.Custom:
                    if (CustomAlgorithm != null)
                        _algorithm = CustomAlgorithm;
                    break;
                case CryptAlgorithm.Aes:
                    _algorithm = new AesAlgorithm(Key, IV);
                    break;
                case CryptAlgorithm.Rijndael:
                    _algorithm = new RijndaelAlgorithm(Key, IV);
                    break;
            }
        }
        public byte[] CryptData(byte[] data, CryptMode mode)
        {
            MemoryStream mem = new MemoryStream();
            using (var crypt = _algorithm.Cryptor(mode))
            using (var stream = new CryptoStream(mem, crypt, CryptoStreamMode.Write))
            {
                stream.Write(data, 0, data.Length);
            }
            return mem.ToArray();
        }
        public async Task<byte[]> CryptDataAsync(byte[] data, CryptMode mode)
        {
            MemoryStream mem = new MemoryStream();
            using (var crypt = _algorithm.Cryptor(mode))
            using (var stream = new CryptoStream(mem, crypt, CryptoStreamMode.Write))
            {
                await stream.WriteAsync(data, 0, data.Length);
            }
            return mem.ToArray();
        }
    }
}
