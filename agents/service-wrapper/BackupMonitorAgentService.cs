using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace BackupMonitorAgent
{
    public class AgentService : ServiceBase
    {
        private readonly string scriptPath;
        private readonly string configPath;
        private readonly string logPath;
        private Thread workerThread;
        private volatile bool stopping;
        private Process child;

        public AgentService(string scriptPath, string configPath, string logPath, string serviceName)
        {
            ServiceName = serviceName;
            CanStop = true;
            CanShutdown = true;
            this.scriptPath = scriptPath;
            this.configPath = configPath;
            this.logPath = logPath;
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            workerThread = new Thread(RunLoop);
            workerThread.IsBackground = true;
            workerThread.Start();
        }

        protected override void OnStop()
        {
            stopping = true;
            StopChild();
            if (workerThread != null && workerThread.IsAlive)
            {
                workerThread.Join(TimeSpan.FromSeconds(10));
            }
        }

        protected override void OnShutdown()
        {
            OnStop();
        }

        private void RunLoop()
        {
            while (!stopping)
            {
                try
                {
                    WriteLog("Starting agent process.");
                    using (var process = CreateProcess())
                    {
                        child = process;
                        process.Start();

                        var stdoutThread = PipeOutput(process.StandardOutput, "OUT");
                        var stderrThread = PipeOutput(process.StandardError, "ERR");

                        process.WaitForExit();
                        stdoutThread.Join(TimeSpan.FromSeconds(2));
                        stderrThread.Join(TimeSpan.FromSeconds(2));

                        WriteLog("Agent process exited with code " + process.ExitCode + ".");
                    }
                }
                catch (Exception ex)
                {
                    WriteLog("Service loop error: " + ex);
                }
                finally
                {
                    child = null;
                }

                if (!stopping)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(5));
                }
            }
        }

        private Process CreateProcess()
        {
            var args = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath) + " -ConfigPath " + Quote(configPath);
            var process = new Process();
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = args;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.WorkingDirectory = Path.GetDirectoryName(scriptPath);
            return process;
        }

        private Thread PipeOutput(StreamReader reader, string prefix)
        {
            var thread = new Thread(() =>
            {
                try
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        WriteLog(prefix + " " + line);
                    }
                }
                catch (Exception ex)
                {
                    WriteLog("Pipe error: " + ex.Message);
                }
            });
            thread.IsBackground = true;
            thread.Start();
            return thread;
        }

        private void StopChild()
        {
            try
            {
                if (child != null && !child.HasExited)
                {
                    child.Kill();
                    child.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                WriteLog("Stop child error: " + ex.Message);
            }
        }

        private void WriteLog(string message)
        {
            try
            {
                var dir = Path.GetDirectoryName(logPath);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.AppendAllText(logPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + message + Environment.NewLine);
            }
            catch
            {
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        public static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.Error.WriteLine("Usage: BackupMonitorAgentService.exe <script.ps1> <config.json> <service.log> [service_name] [/console]");
                Environment.Exit(2);
            }

            var serviceName = "BackupMonitorAgent";
            var console = false;
            if (args.Length > 3)
            {
                if (args[3].Equals("/console", StringComparison.OrdinalIgnoreCase))
                {
                    console = true;
                }
                else
                {
                    serviceName = args[3];
                }
            }
            if (args.Length > 4 && args[4].Equals("/console", StringComparison.OrdinalIgnoreCase))
            {
                console = true;
            }

            var service = new AgentService(args[0], args[1], args[2], serviceName);
            if (console)
            {
                service.OnStart(new string[0]);
                Console.WriteLine("Running. Press ENTER to stop.");
                Console.ReadLine();
                service.OnStop();
                return;
            }

            Run(service);
        }
    }
}
