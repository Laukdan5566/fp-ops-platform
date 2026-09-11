using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Principal;
using System.Text;

namespace BackupMonitorAgent
{
    internal static class InstallerStub
    {
        private static readonly byte[] Marker = Encoding.ASCII.GetBytes("\n--BACKUP_MONITOR_AGENT_PAYLOAD_V1--\n");

        private static int Main(string[] args)
        {
            Console.Title = "Backup Monitor Agent - Instalador";

            try
            {
                if (!IsAdmin())
                {
                    RelaunchAsAdmin();
                    return 0;
                }

                Console.WriteLine("Backup Monitor Agent - Instalador");
                Console.WriteLine("==================================");
                Console.WriteLine();

                var exePath = Process.GetCurrentProcess().MainModule.FileName;
                var payload = ReadPayload(exePath);
                if (payload == null || payload.Length == 0)
                {
                    throw new Exception("Payload embutido nao encontrado neste instalador.");
                }

                var tempRoot = Path.Combine(Path.GetTempPath(), "BackupMonitorAgentSetup-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tempRoot);
                var zipPath = Path.Combine(tempRoot, "payload.zip");
                File.WriteAllBytes(zipPath, payload);
                ZipFile.ExtractToDirectory(zipPath, tempRoot);

                var mode = ReadText(Path.Combine(tempRoot, "install-mode.txt")).Trim().ToLowerInvariant();
                var configName = ReadText(Path.Combine(tempRoot, "config-name.txt")).Trim();
                if (string.IsNullOrEmpty(configName))
                {
                    throw new Exception("config-name.txt nao encontrado no payload.");
                }

                var configPath = Path.Combine(tempRoot, configName);
                if (!File.Exists(configPath))
                {
                    throw new Exception("Config nao encontrada no payload: " + configName);
                }

                Console.WriteLine("Arquivos extraidos em: " + tempRoot);
                Console.WriteLine("Config: " + configName);
                Console.WriteLine("Modo: " + (mode == "legacy" ? "Windows Server 2012 Legacy" : "Padrao"));
                Console.WriteLine();

                var script = mode == "legacy" ? "install-legacy-ws2012.ps1" : "install-windows-agent.ps1";
                var scriptPath = Path.Combine(tempRoot, script);
                if (!File.Exists(scriptPath))
                {
                    throw new Exception("Script de instalacao nao encontrado: " + script);
                }

                var logPath = Path.Combine(Path.GetTempPath(), "backup-monitor-agent-single-exe-install.log");
                var arguments = mode == "legacy"
                    ? "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath) + " -ConfigTemplate " + Quote(configPath) + " -RunNow"
                    : "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath) + " -ConfigTemplate " + Quote(configPath) + " -InstallMode Service -SkipTest -RunNow";

                var code = RunPowerShell(arguments, tempRoot, logPath);
                if (code != 0)
                {
                    throw new Exception("Instalador retornou codigo " + code + ". Log: " + logPath);
                }

                Console.WriteLine();
                Console.WriteLine("Instalacao concluida.");
                Console.WriteLine();
                Console.WriteLine("Para conferir:");
                Console.WriteLine("  Get-Service -Name BackupMonitorAgent");
                Console.WriteLine("  Get-Content \"C:\\ProgramData\\BackupMonitorAgent\\agent.log\" -Tail 50");
                Console.WriteLine("  Get-Content \"C:\\ProgramData\\BackupMonitorAgent\\service.log\" -Tail 50");
                Console.WriteLine();
                Console.WriteLine("Pressione ENTER para fechar.");
                Console.ReadLine();
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("FALHOU:");
                Console.WriteLine(ex.Message);
                Console.WriteLine();
                Console.WriteLine("Pressione ENTER para fechar.");
                Console.ReadLine();
                return 1;
            }
        }

        private static bool IsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void RelaunchAsAdmin()
        {
            var exePath = Process.GetCurrentProcess().MainModule.FileName;
            var psi = new ProcessStartInfo(exePath);
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            Process.Start(psi);
        }

        private static byte[] ReadPayload(string exePath)
        {
            var data = File.ReadAllBytes(exePath);
            var index = LastIndexOf(data, Marker);
            if (index < 0) return null;
            var start = index + Marker.Length;
            var len = data.Length - start;
            var payload = new byte[len];
            Buffer.BlockCopy(data, start, payload, 0, len);
            return payload;
        }

        private static int LastIndexOf(byte[] data, byte[] pattern)
        {
            for (var i = data.Length - pattern.Length; i >= 0; i--)
            {
                var ok = true;
                for (var j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) return i;
            }
            return -1;
        }

        private static string ReadText(string path)
        {
            return File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8) : "";
        }

        private static int RunPowerShell(string arguments, string workingDirectory, string logPath)
        {
            var psi = new ProcessStartInfo("powershell.exe", arguments);
            psi.WorkingDirectory = workingDirectory;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = false;

            using (var process = new Process())
            using (var log = new StreamWriter(logPath, false, Encoding.UTF8))
            {
                process.StartInfo = psi;
                process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    Console.WriteLine(e.Data);
                    log.WriteLine(e.Data);
                    log.Flush();
                };
                process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    Console.WriteLine(e.Data);
                    log.WriteLine(e.Data);
                    log.Flush();
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }
    }
}
