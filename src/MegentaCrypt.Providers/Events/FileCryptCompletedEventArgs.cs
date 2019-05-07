using MegentaCrypt.Core.CryptParams;
using System;
namespace MagentaCrypt.Providers.Events
{
    public class FileCryptCompletedEventArgs : EventArgs
    {
        string _filename;
        string _algorithm;
        long _size;
        string _cryptmode;

        public string Filename
        {
            get
            {
                return _filename;
            }

            set
            {
                _filename = value;
            }
        }
        public string Algorithm
        {
            get
            {
                return _algorithm;
            }

            set
            {
                _algorithm = value;
            }
        }
        public long Size
        {
            get
            {
                return _size;
            }

            set
            {
                _size = value;
            }
        }
        public string Cryptmode
        {
            get
            {
                return _cryptmode;
            }

            set
            {
                _cryptmode = value;
            }
        }

        public FileCryptCompletedEventArgs(string Filename, string Algorithm, long Size, CryptMode Mode)
        {
            Cryptmode = Enum.GetName(typeof(CryptMode), Mode);
            this.Size = Size;
            this.Filename = Filename;
            this.Algorithm = Algorithm;
        }
    }
}
