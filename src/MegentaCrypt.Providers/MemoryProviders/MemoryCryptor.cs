using MagentaCrypt.Providers.Logger;
using MegentaCrypt.Core.Algorithms;
using MegentaCrypt.Core.CryptParams;
using System;
using System.IO;
using System.Threading.Tasks;

namespace MagentaCrypt.Providers.MemoryProviders
{
    public static class MemoryCryptor
    {
        static ILogger _logger = new LogToFile();
        public static MemoryStream CryptData(byte[] data, KeyCrypt key, IVCrypt iv,
            CryptAlgorithm algorithm, CryptMode mode, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && customAlgorithm != null)
                    _core = new CryptCore(key, iv, algorithm, customAlgorithm);
                else if (algorithm == CryptAlgorithm.Custom && customAlgorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                MemoryStream mem = new MemoryStream(_core.CryptData(data, mode));
                return mem;
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while crypting on memory\nmessage:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }

        public static MemoryStream CryptData(MemoryStream data, KeyCrypt key, IVCrypt iv, CryptAlgorithm algorithm, CryptMode mode, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && customAlgorithm != null)
                    _core = new CryptCore(key, iv, algorithm, customAlgorithm);
                else if (algorithm == CryptAlgorithm.Custom && customAlgorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                MemoryStream mem = new MemoryStream(_core.CryptData(data.ToArray(), mode));
                return mem;
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while crypting on memory\nmessage:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
        public static async Task<MemoryStream> CryptDataAsync(byte[] data, KeyCrypt key, IVCrypt iv, CryptAlgorithm algorithm, CryptMode mode, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && customAlgorithm != null)
                    _core = new CryptCore(key, iv, algorithm, customAlgorithm);
                else if (algorithm == CryptAlgorithm.Custom && customAlgorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                MemoryStream mem = new MemoryStream(await _core.CryptDataAsync(data, mode));
                return mem;
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while crypting on memory\nmessage:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
        public static async Task<MemoryStream> CryptDataAsync(MemoryStream data, KeyCrypt key, IVCrypt iv, CryptAlgorithm algorithm, CryptMode mode, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                CryptCore _core;
                if (algorithm == CryptAlgorithm.Custom && customAlgorithm != null)
                    _core = new CryptCore(key, iv, algorithm, customAlgorithm);
                else if (algorithm == CryptAlgorithm.Custom && customAlgorithm == null)
                {
                    _core = new CryptCore(key, iv, CryptAlgorithm.Rijndael);
                    _logger.Log("You have set the custom algorithm but you did not pass an algorithm to use, so the default algorithm(Rijndael) will be used in cryptography.", LogTypes.Server);
                }
                else
                    _core = new CryptCore(key, iv, algorithm);
                MemoryStream mem = new MemoryStream(await _core.CryptDataAsync(data.ToArray(), mode));
                return mem;
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while crypting on memory\nmessage:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
    }
}
