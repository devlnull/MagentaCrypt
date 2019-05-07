using System;

namespace MagentaCrypt.Providers.Events
{
    public class OneStepCryptCompletedEventArgs : EventArgs
    {
        string _name, _cryptmode;
        int _buffersize;
        long _datalength;

        public string Name
        {
            get
            {
                return _name;
            }

            set
            {
                _name = value;
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
        public int BlockSize
        {
            get
            {
                return _buffersize;
            }

            set
            {
                _buffersize = value;
            }
        }
        public long Datalength
        {
            get
            {
                return _datalength;
            }

            set
            {
                _datalength = value;
            }
        }

        public OneStepCryptCompletedEventArgs(string name, string cryptmode, int blocksize, long datalength)
        {
            Name = name;
            Cryptmode = cryptmode;
            BlockSize = blocksize;
            Datalength = datalength;
        }

    }
}
