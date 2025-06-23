using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;
using WebFirewall.Models;

namespace WebFirewall.Services
{

    public class SecurityService
    {
        private readonly ConcurrentDictionary<string, IpBlockInfo> _blockedIps = new();
        private readonly ConcurrentDictionary<string, int> _ipRequestCounts = new();
        private readonly FirewallConfig _config;
        private readonly ILogger<SecurityService> _logger;

        public SecurityService(IOptions<FirewallConfig> config, ILogger<SecurityService> logger)
        {
            _config = config.Value;
            _logger = logger;

            // Initialiser avec les IPs pré-configurées
            foreach (var ip in _config.BlacklistedIps)
            {
                BlockIp(ip, "Pre-configured blacklist");
            }
        }

        public bool IsIpBlocked(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "unknown")
                return false;

            return _blockedIps.ContainsKey(ip);
        }

        public void BlockIp(string ip, string reason)
        {
            if (string.IsNullOrEmpty(ip) || IsIpWhitelisted(ip))
                return;

            var blockInfo = new IpBlockInfo
            {
                IpAddress = ip,
                BlockedAt = DateTime.UtcNow.AddHours(1),
                Reason = reason,
                AttackCount = _ipRequestCounts.GetValueOrDefault(ip, 0)
            };

            _blockedIps.TryAdd(ip, blockInfo);
            _logger.LogWarning("IP {IpAddress} blocked. Reason: {Reason}", ip, reason);
        }

        public void UnblockIp(string ip)
        {
            if (_blockedIps.TryRemove(ip, out var blockInfo))
            {
                _logger.LogInformation("IP {IpAddress} unblocked", ip);
            }
        }

        public List<IpBlockInfo> GetBlockedIps()
        {
            return _blockedIps.Values.OrderByDescending(x => x.BlockedAt).ToList();
        }

        public bool IsIpWhitelisted(string ip)
        {
            if (string.IsNullOrEmpty(ip))
                return false;

            return _config.WhitelistedIps.Contains(ip) || IsLocalhost(ip);
        }

        public void AddToWhitelist(string ip)
        {
            if (!string.IsNullOrEmpty(ip) && !_config.WhitelistedIps.Contains(ip))
            {
                _config.WhitelistedIps.Add(ip);
                // Débloquer l'IP si elle était bloquée
                UnblockIp(ip);
                _logger.LogInformation("IP {IpAddress} added to whitelist", ip);
            }
        }

        public void RemoveFromWhitelist(string ip)
        {
            if (_config.WhitelistedIps.Remove(ip))
            {
                _logger.LogInformation("IP {IpAddress} removed from whitelist", ip);
            }
        }

        public List<string> GetWhitelistedIps()
        {
            return _config.WhitelistedIps.ToList();
        }

        private bool IsLocalhost(string ip)
        {
            if (string.IsNullOrEmpty(ip))
                return false;

            var localhostAddresses = new[]
            {
                "127.0.0.1",
                "::1",
                "localhost"
            };

            return localhostAddresses.Contains(ip) ||
                   (IPAddress.TryParse(ip, out var address) && IPAddress.IsLoopback(address));
        }

        public void IncrementRequestCount(string ip)
        {
            if (string.IsNullOrEmpty(ip))
                return;

            _ipRequestCounts.AddOrUpdate(ip, 1, (key, count) => count + 1);
        }

        public int GetRequestCount(string ip)
        {
            return _ipRequestCounts.GetValueOrDefault(ip, 0);
        }

        public void ResetRequestCounts()
        {
            _ipRequestCounts.Clear();
        }
    }
}