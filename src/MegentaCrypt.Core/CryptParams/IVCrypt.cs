using System;

namespace MegentaCrypt.Core.CryptParams
{
    public struct IVCrypt
    {
        private byte[] _iv;
        public const byte IVLength = 16;
        public byte[] IV
        {
            get
            {
                if (_iv != null)
                    return _iv;
                else
                    throw new ArgumentNullException($"Initial Vector is null.");
            }
            set
            {
                if (value != null)
                    _iv = value;
                else
                    throw new ArgumentNullException($"Initial Vector is null.");
            }
        }
        public IVCrypt(string iv)
        {
            _iv = new byte[] { };
            IV = StringToBytes(iv);
        }
        public IVCrypt(byte[] iv)
        {
            _iv = new byte[] { };
            IV = iv;
        }
        private string BytesToString(byte[] bytes)
        {
            char[] chars = new char[IVLength];
            if (bytes != null)
            {
                for (byte i = 0; i < IVLength; i++)
                    chars[i] = (char)bytes[i];
            }
            else
                throw new ArgumentNullException("Initial Vector is null.");
            return chars.ToString();
        }
        private byte[] StringToBytes(string str)
        {
            byte[] bytes = new byte[IVLength];
            if (!string.IsNullOrEmpty(str))
            {
                for (byte i = 0; i < str.Length; i++)
                    bytes[i] = (byte)str[i];
            }
            else
                throw new ArgumentNullException("Initial Vector is null.");
            return bytes;
        }
        public string StringIV()
        {
            byte[] Iv = IV;
            string iv = BytesToString(Iv);
            if (!string.IsNullOrEmpty(iv))
                return iv;
            else
                throw new ArgumentNullException("Initial Vector is null.");
        }
        public byte[] BytesIV()
        {
            return IV;
        }
    }
}