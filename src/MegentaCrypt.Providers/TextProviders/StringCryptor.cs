using MagentaCrypt.Providers.Logger;
using MegentaCrypt.Core.Algorithms;
using MegentaCrypt.Core.CryptParams;
using System;
using System.Text;
using System.Threading.Tasks;

namespace MagentaCrypt.Providers.TextProviders
{
    public static class StringCryptor
    {
        static readonly ILogger _logger = new LogToFile();
        public static string EncryptData(string data, Encoding encoding, KeyCrypt key,
            IVCrypt iv, CryptAlgorithm algorithm, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                var bdata = encoding.GetBytes(data);
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
                return Convert.ToBase64String(_core.CryptData(bdata, CryptMode.Encrypt));
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while encrypting a string, message:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
        public static async Task<string> EncryptDataAsync(string data, Encoding encoding, KeyCrypt key,
            IVCrypt iv, CryptAlgorithm algorithm, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                var bdata = encoding.GetBytes(data);
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
                return Convert.ToBase64String(await _core.CryptDataAsync(bdata, CryptMode.Encrypt));
            }
            catch (Exception ex)
            {
                ((LogToFile)_logger).LogAsync($"An exception thrown while encrypting a string, message:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
        public static string DecryptData(string data, Encoding encoding, KeyCrypt key,
            IVCrypt iv, CryptAlgorithm algorithm, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                var bdata = Convert.FromBase64String(data);
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
                return encoding.GetString(_core.CryptData(bdata, CryptMode.Decrypt));
            }
            catch (Exception ex)
            {
                _logger.Log($"An exception thrown while decrypting a string, message:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
        public static async Task<string> DecryptDataAsync(string data, Encoding encoding, KeyCrypt key,
            IVCrypt iv, CryptAlgorithm algorithm, ICryptoAlgorithm customAlgorithm = null)
        {
            try
            {
                var bdata = Convert.FromBase64String(data);
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
                return encoding.GetString(await _core.CryptDataAsync(bdata, CryptMode.Decrypt));
            }
            catch (Exception ex)
            {
                ((LogToFile)_logger).LogAsync($"An exception thrown while decrypting a string, message:{ex.Message}", LogTypes.Server);
                throw ex;
            }
        }
    }
}
