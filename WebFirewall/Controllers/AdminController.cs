using Microsoft.AspNetCore.Mvc;
using WebFirewall.Models;
using WebFirewall.Services;

namespace WebFirewall.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly FirewallLogService _logService;
        private readonly ISecurityService _securityService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            FirewallLogService logService,
            ISecurityService securityService,
            ILogger<AdminController> logger)
        {
            _logService = logService;
            _securityService = securityService;
            _logger = logger;
        }

        
        /// Obtenir les statistiques du dashboard        
        [HttpGet("dashboard")]
        public async Task<IActionResult> GetDashboardStats()
        {
            var stats = await _logService.GetDashboardStatsAsync();
            return Ok(stats);
        }
        
       
        /// Vider tous les logs        
        [HttpDelete("logs")]
        public async Task<IActionResult> ClearLogs()
        {
            await _logService.ClearLogsAsync();
            _logger.LogInformation("Logs cleared by admin");
            return Ok(new { message = "Logs cleared successfully" });
        }
        
        /// Obtenir la liste des IPs bloquées        
        [HttpGet("blocked-ips")]
        public IActionResult GetBlockedIps()
        {
            var blockedIps = _securityService.GetBlockedIps();
            return Ok(blockedIps);
        }

        
        /// Bloquer une IP        
        [HttpPost("block-ip")]
        public IActionResult BlockIp([FromBody] BlockIpRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress))
                return BadRequest("IP address is required");

            _securityService.BlockIp(request.IpAddress, request.Reason ?? "Manual block");
            return Ok(new { message = $"IP {request.IpAddress} blocked successfully" });
        }

        
        /// Débloquer une IP        
        [HttpDelete("block-ip/{ip}")]
        public IActionResult UnblockIp(string ip)
        {
            _securityService.UnblockIp(ip);
            return Ok(new { message = $"IP {ip} unblocked successfully" });
        }
        
        /// Obtenir les statistiques en temps réel        
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

}