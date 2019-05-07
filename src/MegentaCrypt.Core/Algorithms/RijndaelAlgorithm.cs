using MegentaCrypt.Core.CryptParams;
using System.Security.Cryptography;

namespace MegentaCrypt.Core.Algorithms
{
    public class RijndaelAlgorithm : ICryptoAlgorithm
    {
        Rijndael _rijndael;
        KeyCrypt _key;
        public string Name { get; set; }
        IVCrypt _iv;
        public KeyCrypt Key
        {
            get { return _key; }
        }
        public IVCrypt IV
        {
            get { return _iv; }
        }
        Rijndael CreateAlgorithm()
        {
            var algo = Rijndael.Create();
            algo.Padding = PaddingMode.Zeros;
            return algo;
        }
        public RijndaelAlgorithm(KeyCrypt key, IVCrypt iv)
        {
            this.Name = "Rijndael";
            _rijndael = this.CreateAlgorithm();
            _key = key;
            _iv = iv;
        }
        public RijndaelAlgorithm(byte[] key, byte[] iv)
        {
            _rijndael = this.CreateAlgorithm();
            _key.Key = key;
            _iv.IV = iv;
        }
        public ICryptoTransform Cryptor(CryptMode mode)
        {
            if (mode == CryptMode.Encrypt)
                return _rijndael.CreateEncryptor(Key.BytesKey(), IV.BytesIV());
            else
                return _rijndael.CreateDecryptor(Key.BytesKey(), IV.BytesIV());
        }
    }
}
