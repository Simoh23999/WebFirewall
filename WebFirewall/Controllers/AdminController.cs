using Microsoft.AspNetCore.Mvc;
using WebFirewall.Models;
using WebFirewall.Services;

namespace WebFirewall.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly IFirewallLogService _logService;
        private readonly ISecurityService _securityService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            IFirewallLogService logService,
            ISecurityService securityService,
            ILogger<AdminController> logger)
        {
            _logService = logService;
            _securityService = securityService;
            _logger = logger;
        }

        /// <summary>
        /// Obtenir les statistiques du dashboard
        /// </summary>
        [HttpGet("dashboard")]
        public async Task<IActionResult> GetDashboardStats()
        {
            var stats = await _logService.GetDashboardStatsAsync();
            return Ok(stats);
        }

        /// <summary>
        /// Obtenir tous les logs
        /// </summary>
        [HttpGet("logs")]
        public async Task<IActionResult> GetLogs([FromQuery] int count = 100)
        {
            var logs = await _logService.GetLogsAsync(count);
            return Ok(logs);
        }

        /// <summary>
        /// Obtenir les logs par IP
        /// </summary>
        [HttpGet("logs/ip/{ip}")]
        public async Task<IActionResult> GetLogsByIp(string ip, [FromQuery] int count = 50)
        {
            var logs = await _logService.GetLogsByIpAsync(ip, count);
            return Ok(logs);
        }

        /// <summary>
        /// Obtenir les logs par type d'attaque
        /// </summary>
        [HttpGet("logs/attack/{attackType}")]
        public async Task<IActionResult> GetLogsByAttackType(string attackType, [FromQuery] int count = 50)
        {
            var logs = await _logService.GetLogsByAttackTypeAsync(attackType, count);
            return Ok(logs);
        }

        /// <summary>
        /// Vider tous les logs
        /// </summary>
        [HttpDelete("logs")]
        public async Task<IActionResult> ClearLogs()
        {
            await _logService.ClearLogsAsync();
            _logger.LogInformation("Logs cleared by admin");
            return Ok(new { message = "Logs cleared successfully" });
        }

        /// <summary>
        /// Obtenir la liste des IPs bloquées
        /// </summary>
        [HttpGet("blocked-ips")]
        public IActionResult GetBlockedIps()
        {
            var blockedIps = _securityService.GetBlockedIps();
            return Ok(blockedIps);
        }

        /// <summary>
        /// Bloquer une IP
        /// </summary>
        [HttpPost("block-ip")]
        public IActionResult BlockIp([FromBody] BlockIpRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress))
                return BadRequest("IP address is required");

            _securityService.BlockIp(request.IpAddress, request.Reason ?? "Manual block");
            return Ok(new { message = $"IP {request.IpAddress} blocked successfully" });
        }

        /// <summary>
        /// Débloquer une IP
        /// </summary>
        [HttpDelete("block-ip/{ip}")]
        public IActionResult UnblockIp(string ip)
        {
            _securityService.UnblockIp(ip);
            return Ok(new { message = $"IP {ip} unblocked successfully" });
        }

        /// <summary>
        /// Obtenir la liste des IPs en whitelist
        /// </summary>
        [HttpGet("whitelist")]
        public IActionResult GetWhitelist()
        {
            var whitelistedIps = _securityService.GetWhitelistedIps();
            return Ok(whitelistedIps);
        }

        /// <summary>
        /// Ajouter une IP à la whitelist
        /// </summary>
        [HttpPost("whitelist")]
        public IActionResult AddToWhitelist([FromBody] WhitelistRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress))
                return BadRequest("IP address is required");

            _securityService.AddToWhitelist(request.IpAddress);
            return Ok(new { message = $"IP {request.IpAddress} added to whitelist" });
        }

        /// <summary>
        /// Retirer une IP de la whitelist
        /// </summary>
        [HttpDelete("whitelist/{ip}")]
        public IActionResult RemoveFromWhitelist(string ip)
        {
            _securityService.RemoveFromWhitelist(ip);
            return Ok(new { message = $"IP {ip} removed from whitelist" });
        }

        /// <summary>
        /// Obtenir les statistiques en temps réel
        /// </summary>
        [HttpGet("stats/realtime")]
        public async Task<IActionResult> GetRealtimeStats()
        {
            var stats = await _logService.GetDashboardStatsAsync();
            var blockedIps = _securityService.GetBlockedIps();

            return Ok(new
            {
                timestamp = DateTime.UtcNow,
                totalBlocked = stats.BlockedRequests,
                totalSuspicious = stats.SuspiciousRequests,
                blockedIpsCount = blockedIps.Count,
                topAttackTypes = stats.AttackTypes.OrderByDescending(x => x.Value).Take(5),
                recentActivity = stats.RecentLogs.Take(10)
            });
        }
    }

    public class BlockIpRequest
    {
        public string IpAddress { get; set; } = string.Empty;
        public string? Reason { get; set; }
    }

    public class WhitelistRequest
    {
        public string IpAddress { get; set; } = string.Empty;
    }
}