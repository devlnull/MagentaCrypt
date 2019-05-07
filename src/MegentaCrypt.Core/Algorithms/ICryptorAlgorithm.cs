using MegentaCrypt.Core.CryptParams;
using System.Security.Cryptography;

namespace MegentaCrypt.Core.Algorithms
{
    public interface ICryptoAlgorithm
    {
        string Name { get; }
        KeyCrypt Key { get; }
        IVCrypt IV { get; }
        ICryptoTransform Cryptor(CryptMode mode);
    }
}
