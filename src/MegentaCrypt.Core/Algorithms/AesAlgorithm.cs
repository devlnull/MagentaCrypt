using MegentaCrypt.Core.CryptParams;
using System.Security.Cryptography;

namespace MegentaCrypt.Core.Algorithms
{
    public class AesAlgorithm : ICryptoAlgorithm
    {
        Aes _aes;
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

        Aes CreateAlgorithm()
        {
            var algo = Aes.Create();
            algo.Padding = PaddingMode.Zeros;
            return algo;
        }
        public AesAlgorithm(KeyCrypt key, IVCrypt iv)
        {
            this.Name = "Aes";
            _aes = this.CreateAlgorithm();
            _key = key;
            _iv = iv;
        }
        public AesAlgorithm(byte[] key, byte[] iv)
        {
            _aes = this.CreateAlgorithm();
            _key.Key = key;
            _iv.IV = iv;
        }
        public ICryptoTransform Cryptor(CryptMode mode)
        {
            if (mode == CryptMode.Encrypt)
                return _aes.CreateEncryptor(Key.BytesKey(), IV.BytesIV());
            else
                return _aes.CreateDecryptor(Key.BytesKey(), IV.BytesIV());
        }
    }
}