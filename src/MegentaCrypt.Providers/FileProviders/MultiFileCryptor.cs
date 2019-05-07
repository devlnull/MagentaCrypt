using MagentaCrypt.Providers.Events;
using MagentaCrypt.Providers.Logger;
using MegentaCrypt.Core.Algorithms;
using MegentaCrypt.Core.CryptParams;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MagentaCrypt.Providers.FileProviders
{
    public class MultiFileCryptor
    {
        readonly object _locker = new object();
        const string Extension = "mgt";
        KeyCrypt key;
        IVCrypt iv;
        ILogger logger;
        ICryptoAlgorithm _algorithm;
        public event EventHandler<FileCryptCompletedEventArgs> OneFileCryptCompleted;
        public event EventHandler<EventArgs> CryptographyCompleted;
        int blocksize;
        public Dictionary<string, string> files;
        public Dictionary<string, string> Files
        {
            get
            {
                return files;
            }
        }
        public KeyCrypt Key
        {
            get
            {
                return key;
            }
        }
        public IVCrypt Iv
        {
            get
            {
                return iv;
            }
        }
        public int Blocksize
        {
            get
            {
                return blocksize;
            }
        }

        public MultiFileCryptor(Dictionary<string, string> files, KeyCrypt key,
            IVCrypt iv, ICryptoAlgorithm customAlgorithm = null, ILogger logger = null, int blocksize = 1048576)
        {
            this.files = new Dictionary<string, string>(files);
            this.key = key;
            this.iv = iv;
            this.blocksize = blocksize;
            this._algorithm = customAlgorithm;
            if (logger == null)
                this.logger = new LogToFile();
            else
                this.logger = logger;
        }
        public MultiFileCryptor(Dictionary<FileInfo, FileInfo> files,
            KeyCrypt key, IVCrypt iv, ICryptoAlgorithm customAlgorithm = null,
            ILogger logger = null, int blocksize = 1048576)
        {
            this.key = key;
            this.iv = iv;
            this.blocksize = blocksize;
            this._algorithm = customAlgorithm;
            if (logger == null)
                this.logger = new LogToFile();
            else
                this.logger = logger;
            this.files = new Dictionary<string, string>(files.Count());
            foreach (var file in files)
                AddFile(file.Key.FullName, file.Value.FullName);
        }
        public void AddFile(string filename, string destination)
        {
            filename = DoesExist(filename);
            if (!string.IsNullOrEmpty(filename))
                this.files.Add(filename, destination);
        }
        public bool RemoveFile(string filename)
        {
            return this.files.Remove(filename);
        }
        private string DoesExist(string filename)
        {
            if (File.Exists(filename))
                return filename;
            else
            {
                logger.Log($"{filename} does not exist.", LogTypes.Client);
                return null;
            }
        }

        public void StartCrypt(CryptMode mode, CryptAlgorithm algorithm)
        {
            FileCryptor[] cryptors = new FileCryptor[Files.Count];
            Task[] tasks = new Task[Files.Count];

            if (mode == CryptMode.Encrypt)
            {
                for (int i = 0; i < tasks.Length; i++)
                {
                    int ii = i;
                    tasks[i] = new Task(() =>
                    {
                        using (cryptors[ii] = new FileCryptor(files.ElementAt(ii).Key,
                            AppendExtension(files.ElementAt(ii).Value, Extension), _algorithm, this.logger, this.Blocksize))
                        {
                            cryptors[ii].CryptCompleted += new EventHandler<FileCryptCompletedEventArgs>(FileCryptCompleted);
                            cryptors[ii].OneStepCompleted += new EventHandler<OneStepCryptCompletedEventArgs>(OneStepFileCryptCompleted);
                            cryptors[ii].Crypt(Key, Iv, mode, algorithm);
                        }
                    });
                }
                foreach (var task in tasks)
                    task.Start();
                Task.WhenAll(tasks).GetAwaiter().OnCompleted(() =>
                {
                    OnCryptographyCompleted();
                });
            }
            else
            {
                for (int i = 0; i < tasks.Length; i++)
                {
                    int ii = i;
                    tasks[i] = new Task(() =>
                    {
                        using (cryptors[ii] = new FileCryptor(files.ElementAt(ii).Key,
                            ClearExtension(files.ElementAt(ii).Value), _algorithm, this.logger, this.Blocksize))
                        {
                            cryptors[ii].CryptCompleted += new EventHandler<FileCryptCompletedEventArgs>(FileCryptCompleted);
                            cryptors[ii].OneStepCompleted += new EventHandler<OneStepCryptCompletedEventArgs>(OneStepFileCryptCompleted);
                            cryptors[ii].Crypt(Key, Iv, mode, algorithm);
                        }
                    });
                }
                foreach (var task in tasks)
                    task.Start();
                Task.WhenAll(tasks).GetAwaiter().OnCompleted(() =>
                {
                    OnCryptographyCompleted();
                });
            }
        }

        private void OneStepFileCryptCompleted(object sender, OneStepCryptCompletedEventArgs e)
        {
            lock (_locker)
                logger.Log($"{e.BlockSize} of {e.Datalength} of {e.Name} has been successfully {e.Cryptmode}ed.", LogTypes.Client);
        }

        private void FileCryptCompleted(object sender, FileCryptCompletedEventArgs e)
        {
            OnFileCompleted(e);
            lock (_locker)
                logger.Log($"{e.Filename} with size of {e.Size} bytes has been successfully {e.Cryptmode}ed under {e.Algorithm} algorithm.", LogTypes.Client);
        }

        private void OnFileCompleted(FileCryptCompletedEventArgs ev)
        {
            OneFileCryptCompleted?.Invoke(this, ev);
        }
        private void OnCryptographyCompleted()
        {
            CryptographyCompleted?.Invoke(this, EventArgs.Empty);
        }

        private string AppendExtension(string filename, string extension)
        {
            lock (_locker)
            {
                filename = filename.Insert(filename.Length, $".{extension}");
                return $"{filename}";
            }
        }
        private string ClearExtension(string filename)
        {
            lock (_locker)
            {
                int lastDot = filename.LastIndexOf('.');
                filename = filename.Remove(lastDot, filename.Length - lastDot);
                return $"{filename}";
            }
        }
    }
}
