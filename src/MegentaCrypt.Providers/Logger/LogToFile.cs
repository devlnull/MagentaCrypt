using System;
using System.IO;

namespace MagentaCrypt.Providers.Logger
{
    public class LogToFile : ILogger
    {
        string logfilename;
        readonly object _locker = new object();
        public LogToFile()
        {
            logfilename = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.ApplicationData),
                $"logfile-{DateTime.Now.ToString("yyyyMMdd")}.log");
        }
        public void Log(string logMessage, LogTypes type)
        {
            lock (_locker)
            {       
                using (StreamWriter writer = new StreamWriter(logfilename, true))
                {
                    string logtypename = Enum.GetName(typeof(LogTypes), type);
                    writer.WriteLine($"{logtypename}# {logMessage}");
                }
            }
        }
        public async void LogAsync(string logMessage, LogTypes type)
        {
            using (StreamWriter writer = new StreamWriter(logfilename, true))
            {
                string logtypename = Enum.GetName(typeof(LogTypes), type);
                await writer.WriteLineAsync($"{logtypename}# {logMessage}");
            }
        }
    }
}
