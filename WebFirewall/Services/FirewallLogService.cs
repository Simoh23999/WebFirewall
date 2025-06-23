using System.Collections.Concurrent;
using System.Text.Json;
using WebFirewall.Models;

namespace WebFirewall.Services
{

    public class FirewallLogService
    {
        private readonly ConcurrentQueue<FirewallLogEntry> _logsQueue = new();
        private readonly string _logFilePath;
        private readonly ILogger<FirewallLogService> _logger;
        private readonly SemaphoreSlim _fileSemaphore = new(1, 1);

        public FirewallLogService(ILogger<FirewallLogService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _logFilePath = configuration.GetValue<string>("FirewallConfig:LogFilePath") ?? "firewall_logs.json";

            // Charger les logs existants au démarrage
            _ = Task.Run(LoadExistingLogs);
        }

        //enregistrer une nouvelle log
        public async Task LogAsync(FirewallLogEntry entry)
        {
            try
            {
                _logsQueue.Enqueue(entry);

                // Sauvegarder en fichier de maniere asynchrone
                await SaveLogToFileAsync(entry);

                _logger.LogInformation(">>> Logged suspicious activity: {AttackType} from {ClientIp}",
                    entry.AttackType, entry.ClientIp);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging firewall entry");
            }
        }

        public async Task<List<FirewallLogEntry>> GetLogsAsync(int count = 100)
        {
            await Task.CompletedTask;
            return _logsQueue.Reverse().Take(count).ToList();
        }

        public async Task<List<FirewallLogEntry>> GetLogsByIpAsync(string ip, int count = 50)
        {
            await Task.CompletedTask;
            return _logsQueue.Where(log => log.ClientIp == ip)
                           .Reverse()// ===========================  peut etre supp =========================================
                           .Take(count)
                           .ToList();
        }

        public async Task<List<FirewallLogEntry>> GetLogsByAttackTypeAsync(string attackType, int count = 50)
        {
            await Task.CompletedTask;
            return _logsQueue.Where(log => log.AttackType == attackType)
                           .Reverse()
                           .Take(count)
                           .ToList();
        }

        //Genere les statistiques pour le dashboard
        public async Task<DashboardStats> GetDashboardStatsAsync()
        {
            await Task.CompletedTask;

            var logs = _logsQueue.ToList();
            var last24Hours = logs.Where(l => l.Timestamp > DateTime.UtcNow.AddHours(-24)).ToList();

            var stats = new DashboardStats
            {
                TotalRequests = logs.Count,
                BlockedRequests = logs.Count(l => l.Action == "BLOCKED"),                
                AttackTypes = logs.GroupBy(l => l.AttackType)
                                 .ToDictionary(g => g.Key, g => g.Count()),
                TopAttackerIps = logs.GroupBy(l => l.ClientIp)
                                   .OrderByDescending(g => g.Count())
                                   .Take(10)
                                   .ToDictionary(g => g.Key, g => g.Count()),
                RecentLogs = logs.OrderByDescending(l => l.Timestamp).Take(20).ToList()
            };

            return stats;
        }

        public async Task ClearLogsAsync()
        {
            await _fileSemaphore.WaitAsync();
            try
            {
                while (_logsQueue.TryDequeue(out _)) { }

                if (File.Exists(_logFilePath))
                {
                    File.Delete(_logFilePath);
                }

                _logger.LogInformation("Firewall logs cleared !!!!!!!!!!!!");
            }
            finally
            {
                _fileSemaphore.Release();
            }
        }

        //enregistrer une nouvelle log
        private async Task SaveLogToFileAsync(FirewallLogEntry entry)
        {
            await _fileSemaphore.WaitAsync();
            try
            {
                var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions
                {
                    WriteIndented = false
                });

                await File.AppendAllTextAsync(_logFilePath, json + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors du sauvgard log dans le fichier");
            }
            finally
            {
                _fileSemaphore.Release();
            }
        }

        //Charge les logs 
        private async Task LoadExistingLogs()
        {
            try
            {
                if (!File.Exists(_logFilePath))
                    return;

                var lines = await File.ReadAllLinesAsync(_logFilePath);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    try
                    {
                        var entry = JsonSerializer.Deserialize<FirewallLogEntry>(line);
                        if (entry != null)
                        {
                            _logsQueue.Enqueue(entry);
                        }
                    }
                    catch (JsonException)
                    {
                        // ignorer les lignes malformees au cas s'il y a un
                        continue;
                    }
                }

                _logger.LogInformation(">>> Loaded {Count} existing firewall logs", _logsQueue.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ">>>>>>>>>>>  Error loading existing logs");
            }
        }
    }
}