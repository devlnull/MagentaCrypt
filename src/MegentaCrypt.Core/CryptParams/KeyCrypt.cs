using System;

namespace MegentaCrypt.Core.CryptParams
{
    public struct KeyCrypt
    {
        private byte[] _key;
        public const byte KeyLength = 16;
        public byte[] Key
        {
            get
            {
                if (_key != null)
                    return _key;
                else
                    throw new ArgumentNullException($"Key is null.");
            }
            set
            {
                if (value != null)
                    _key = value;
                else
                    throw new ArgumentNullException($"Key is null.");
            }
        }
        public KeyCrypt(string key)
        {
            _key = new byte[] { };
            Key = StringToBytes(key);
        }
        public KeyCrypt(byte[] key)
        {
            _key = new byte[] { };
            Key = key;
        }
        private string BytesToString(byte[] bytes)
        {
            char[] chars = new char[KeyLength];
            if (bytes != null)
            {
                for (byte i = 0; i < KeyLength; i++)
                    chars[i] = (char)bytes[i];
            }
            else
                throw new ArgumentNullException("Key is null.");
            return chars.ToString();
        }
        private byte[] StringToBytes(string str)
        {
            byte[] bytes = new byte[KeyLength];
            if (!string.IsNullOrEmpty(str))
            {
                for (byte i = 0; i < str.Length; i++)
                    bytes[i] = (byte)str[i];
            }
            else
                throw new ArgumentNullException("Key is null.");
            return bytes;
        }
        public string StringKey()
        {
            byte[] Key = this.Key;
            string key = BytesToString(Key);
            if (!string.IsNullOrEmpty(key))
                return key;
            else
                throw new ArgumentNullException("Key is null.");
        }
        public byte[] BytesKey()
        {
            return Key;
        }
    }
}
