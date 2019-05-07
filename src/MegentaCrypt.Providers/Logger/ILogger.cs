namespace MagentaCrypt.Providers.Logger
{
    public enum LogTypes
    {
        Server,
        Client
    }
    public interface ILogger
    {
        void Log(string logMessage, LogTypes type);
    }
}
