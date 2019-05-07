using MagentaCrypt.Providers.Events;
using MagentaCrypt.Providers.Logger;
using MegentaCrypt.Core.Algorithms;
using MegentaCrypt.Core.CryptParams;
using System;
using System.IO;
using System.Threading.Tasks;

namespace MagentaCrypt.Providers.FileProviders
{
    public class FileCryptor : IDisposable
    {
        FileInfo _currentFileInfo;
        FileInfo _cryptFileInfo;
        ILogger _logger;
        ICryptoAlgorithm _algorithm;
        FileStream _reader;
        FileStream _writer;
        public event EventHandler<OneStepCryptCompletedEventArgs> OneStepCompleted;
        public event EventHandler<FileCryptCompletedEventArgs> CryptCompleted;
        readonly object _locker = new object();
        int _blocksize;
        int _blockStepsLen, _currentStep;
        int _readerPtr, _writerPtr;
        public FileInfo Info
        {
            get
            {
                return _currentFileInfo;
            }
        }
        public ILogger Logger
        {
            get
            {
                return _logger;
            }
        }
        public int BlockSize
        {
            get
            {
                return _blocksize;
            }
        }
        public FileInfo CryptFileInfo
        {
            get
            {
                return _cryptFileInfo;
            }
        }


        public FileCryptor(string filename, string CryptFilename,
            ICryptoAlgorithm customAlgorithm = null, ILogger logger = null, int blocksize = 1024)
        {
            if (customAlgorithm != null)
                _algorithm = customAlgorithm;
            if (logger == null)
                _logger = new LogToFile();
            else
                this._logger = logger;
            if (!DoesExist(filename))
                logger.Log($"{filename} does not exist.", LogTypes.Server);
            _currentFileInfo = new FileInfo(filename);
            if (DoesExist(CryptFilename))
                logger.Log($"{CryptFilename} already exist.", LogTypes.Server);
            _cryptFileInfo = new FileInfo(CryptFilename);
            if (blocksize < 1024)
                logger.Log($"block size must be greater than 1024 bytes.", LogTypes.Server);
            if (blocksize > Info.Length)
                logger.Log($"Although your block size for {filename} is greater than file size but we've set the file size as block size.", LogTypes.Server);
            _blocksize = blocksize;
            if (Info.Length == blocksize)
                _blockStepsLen = (int)(Info.Length / blocksize);
            else
                _blockStepsLen = (int)((Info.Length / blocksize) + 1);
            _readerPtr = 0;
            _writerPtr = 0;
        }
        public FileCryptor(FileInfo fileinfo, FileInfo CryptFilename,
            ICryptoAlgorithm customAlgorithm = null, ILogger logger = null, int blocksize = 1024)
            : this(fileinfo.FullName, CryptFilename.FullName,
                  customAlgorithm: customAlgorithm, logger: logger, blocksize: blocksize)
        {
        }

        public void Crypt(KeyCrypt key, IVCrypt iv, CryptMode mode, CryptAlgorithm algorithm)
        {
            while (++_currentStep <= _blockStepsLen)
            {
                var block = ReadBlock();
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && _algorithm != null)
                    _core = new CryptCore(key, iv, algorithm, _algorithm);
                else if (algorithm == CryptAlgorithm.Custom && _algorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                var crypt = _core.CryptData(block, mode);
                WriteBlock(crypt);
                OnStepCompleted(new OneStepCryptCompletedEventArgs(Info.FullName,
                    Enum.GetName(typeof(CryptMode), CryptMode.Encrypt), BlockSize, Info.Length));
            }
            if (algorithm == CryptAlgorithm.Custom)
                OnCryptCompleted(new FileCryptCompletedEventArgs(Info.FullName, _algorithm.Name, Info.Length, mode));
            else
                OnCryptCompleted(new FileCryptCompletedEventArgs(Info.FullName,
                    Enum.GetName(typeof(CryptAlgorithm), algorithm), Info.Length, mode));
        }

        public async Task CryptAsync(KeyCrypt key, IVCrypt iv, CryptMode mode, CryptAlgorithm algorithm)
        {
            while (++_currentStep <= _blockStepsLen)
            {
                var block = await ReadBlockAsync();
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && _algorithm != null)
                    _core = new CryptCore(key, iv, algorithm, _algorithm);
                else if (algorithm == CryptAlgorithm.Custom && _algorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                var crypt = await _core.CryptDataAsync(block, mode);
                await WriteBlockAsync(crypt);
                OnStepCompleted(new OneStepCryptCompletedEventArgs(Info.FullName,
                    Enum.GetName(typeof(CryptMode), CryptMode.Encrypt), BlockSize, Info.Length));
            }
        }

        private bool DoesExist(string filename)
        {
            if (!File.Exists(filename))
                return false;
            return true;
        }

        private byte[] ReadBlock()
        {
            lock (_locker)
            {
                byte[] temp;
                using (_reader = new FileStream(Info.FullName, FileMode.Open))
                {
                    if (!(_reader.CanRead && _reader.CanSeek))
                    {
                        _logger.Log($"Cannot read or seek to {Info.FullName}", LogTypes.Server);
                        return null;
                    }
                    _reader.Seek(_readerPtr, SeekOrigin.Begin);
                    if ((_reader.Length - _reader.Position) > BlockSize)
                    {
                        temp = new byte[BlockSize];
                        _reader.Read(temp, 0, BlockSize);
                        _readerPtr += BlockSize;
                    }
                    else
                    {
                        int remained = (int)(_reader.Length - _reader.Position);
                        temp = new byte[remained];
                        _reader.Read(temp, 0, (remained));
                        _readerPtr += remained;
                    }
                }
                return temp;
            }
        }
        private async Task<byte[]> ReadBlockAsync()
        {
            byte[] temp;
            using (_reader = new FileStream(Info.FullName, FileMode.Open))
            {
                if (!(_reader.CanRead && _reader.CanSeek))
                {
                    _logger.Log($"Cannot read or seek to {Info.FullName}", LogTypes.Server);
                    return null;
                }
                _reader.Seek(_readerPtr, SeekOrigin.Begin);
                if ((_reader.Length - _reader.Position) > BlockSize)
                {
                    temp = new byte[BlockSize];
                    await _reader.ReadAsync(temp, 0, BlockSize);
                    _readerPtr += BlockSize;
                }
                else
                {
                    int remained = (int)(_reader.Length - _reader.Position);
                    temp = new byte[remained];
                    await _reader.ReadAsync(temp, 0, (remained));
                    _readerPtr += remained;
                }
            }
            return temp;
        }
        private void WriteBlock(byte[] block)
        {
            lock (_locker)
            {
                byte[] temp = block;
                using (_writer = new FileStream(CryptFileInfo.FullName, FileMode.Append))
                {
                    if (!(_writer.CanWrite && _writer.CanSeek))
                    {
                        Logger.Log($"Cannot write or seek to {CryptFileInfo}", LogTypes.Server);
                        return;
                    }
                    _writer.Write(temp, 0, temp.Length);
                    _writerPtr += temp.Length;
                }
            }
        }
        private async Task WriteBlockAsync(byte[] block)
        {
            byte[] temp = block;
            using (_writer = new FileStream(CryptFileInfo.FullName, FileMode.Append))
            {
                if (!(_writer.CanWrite && _writer.CanSeek))
                {
                    _logger.Log($"Cannot write or seek to {CryptFileInfo}", LogTypes.Server);
                    return;
                }
                await _writer.WriteAsync(temp, 0, temp.Length);
                _writerPtr += temp.Length;
            }
        }

        protected virtual void OnStepCompleted(OneStepCryptCompletedEventArgs ev)
        {
            OneStepCompleted?.Invoke(this, ev);
        }

        protected virtual void OnCryptCompleted(FileCryptCompletedEventArgs ev)
        {
            CryptCompleted?.Invoke(this, ev);
        }

        public void Dispose()
        {
            _reader.Dispose();
            _writer.Dispose();
        }
    }
}
