namespace WebFirewall.Models
{
    public class FirewallConfig
    {
        public bool BlockMaliciousRequests { get; set; } = true;
        public int RateLimitPerMinute { get; set; } = 100;
        public bool LogSuspiciousActivity { get; set; } = true;
        public string LogFilePath { get; set; } = "firewall_logs.json";
        public List<string> WhitelistedIps { get; set; } = new();
        public List<string> BlacklistedIps { get; set; } = new();
    }

    public class FirewallLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string ClientIp { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string QueryString { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public string AttackType { get; set; } = string.Empty;
        public string DetectedPattern { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new();     
    }

    public class AttackDetectionResult
    {
        public bool IsAttack { get; set; } = false;
        public AttackType AttackType { get; set; }
        public string DetectedPattern { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
    }

    public enum AttackType
    {
        XSS,
        SQLi,
        LFI,
        DoS,
        SSRF,
        Unknown
    }

    public class DashboardStats
    {
        public int TotalRequests { get; set; }
        public int BlockedRequests { get; set; }
        public int SuspiciousRequests { get; set; }
        public Dictionary<string, int> AttackTypes { get; set; } = new();
        public Dictionary<string, int> TopAttackerIps { get; set; } = new();
        public List<FirewallLogEntry> RecentLogs { get; set; } = new();
    }

    public class IpBlockInfo
    {
        public string IpAddress { get; set; } = string.Empty;
        public DateTime BlockedAt { get; set; }
        public string Reason { get; set; } = string.Empty;
        public int AttackCount { get; set; }
    }
}