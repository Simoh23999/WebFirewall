using Microsoft.Extensions.Options;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using WebFirewall.Models;
using WebFirewall.Services;

namespace WebFirewall.Middleware
{
    public class FirewallMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IFirewallLogService _logService;
        private readonly ISecurityService _securityService;
        private readonly FirewallConfig _config;
        private readonly ILogger<FirewallMiddleware> _logger;

        // Patterns de détection d'attaques
        private readonly Dictionary<AttackType, List<Regex>> _attackPatterns;

        public FirewallMiddleware(
            RequestDelegate next,
            IFirewallLogService logService,
            ISecurityService securityService,
            IOptions<FirewallConfig> config,
            ILogger<FirewallMiddleware> logger)
        {
            _next = next;
            _logService = logService;
            _securityService = securityService;
            _config = config.Value;
            _logger = logger;
            _attackPatterns = InitializeAttackPatterns();
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var request = context.Request;
            var clientIp = GetClientIpAddress(context);

            // Vérifier IP bloquée
            if (_securityService.IsIpBlocked(clientIp))
            {
                await BlockRequest(context, "IP_BLOCKED", clientIp);
                return;
            }

            // Analyser la requête
            var attackDetected = await AnalyzeRequest(context);
            if (attackDetected.IsAttack)
            {
                await LogSuspiciousActivity(context, attackDetected, clientIp);

                if (_config.BlockMaliciousRequests)
                {
                    await BlockRequest(context, attackDetected.AttackType.ToString(), clientIp);
                    return;
                }
            }

            await _next(context);
        }

        private async Task<AttackDetectionResult> AnalyzeRequest(HttpContext context)
        {
            var request = context.Request;
            var result = new AttackDetectionResult();

            // Analyser URL
            var urlAnalysis = AnalyzeUrl(request.Path + request.QueryString);
            if (urlAnalysis.IsAttack)
                return urlAnalysis;

            // Analyser headers
            var headerAnalysis = AnalyzeHeaders(request.Headers);
            if (headerAnalysis.IsAttack)
                return headerAnalysis;

            // Analyser le body si présent
            if (request.ContentLength > 0)
            {
                request.EnableBuffering();
                var body = await ReadRequestBody(request);
                var bodyAnalysis = AnalyzeBody(body);
                if (bodyAnalysis.IsAttack)
                    return bodyAnalysis;
            }

            // Vérifier SSRF
            var ssrfAnalysis = AnalyzeForSSRF(request);
            if (ssrfAnalysis.IsAttack)
                return ssrfAnalysis;

            return result;
        }

        private AttackDetectionResult AnalyzeUrl(string url)
        {
            foreach (var patternGroup in _attackPatterns)
            {
                foreach (var pattern in patternGroup.Value)
                {
                    if (pattern.IsMatch(url))
                    {
                        return new AttackDetectionResult
                        {
                            IsAttack = true,
                            AttackType = patternGroup.Key,
                            DetectedPattern = pattern.ToString(),
                            Payload = url
                        };
                    }
                }
            }
            return new AttackDetectionResult();
        }

        private AttackDetectionResult AnalyzeHeaders(IHeaderDictionary headers)
        {
            foreach (var header in headers)
            {
                var headerValue = string.Join(" ", header.Value);

                foreach (var patternGroup in _attackPatterns)
                {
                    foreach (var pattern in patternGroup.Value)
                    {
                        if (pattern.IsMatch(headerValue))
                        {
                            return new AttackDetectionResult
                            {
                                IsAttack = true,
                                AttackType = patternGroup.Key,
                                DetectedPattern = pattern.ToString(),
                                Payload = $"{header.Key}: {headerValue}"
                            };
                        }
                    }
                }
            }
            return new AttackDetectionResult();
        }

        private AttackDetectionResult AnalyzeBody(string body)
        {
            foreach (var patternGroup in _attackPatterns)
            {
                foreach (var pattern in patternGroup.Value)
                {
                    if (pattern.IsMatch(body))
                    {
                        return new AttackDetectionResult
                        {
                            IsAttack = true,
                            AttackType = patternGroup.Key,
                            DetectedPattern = pattern.ToString(),
                            Payload = body.Length > 100 ? body.Substring(0, 100) + "..." : body
                        };
                    }
                }
            }
            return new AttackDetectionResult();
        }

        private AttackDetectionResult AnalyzeForSSRF(HttpRequest request)
        {
            // Vérifier les paramètres qui pourraient contenir des URLs
            var urlParams = new[] { "url", "uri", "link", "redirect", "callback", "target" };

            foreach (var param in urlParams)
            {
                if (request.Query.ContainsKey(param))
                {
                    var value = request.Query[param].ToString();
                    if (IsSSRFAttempt(value))
                    {
                        return new AttackDetectionResult
                        {
                            IsAttack = true,
                            AttackType = AttackType.SSRF,
                            DetectedPattern = "SSRF_URL_PARAMETER",
                            Payload = value
                        };
                    }
                }
            }

            return new AttackDetectionResult();
        }

        private bool IsSSRFAttempt(string url)
        {
            if (string.IsNullOrEmpty(url)) return false;

            var ssrfPatterns = new[]
            {
                @"^https?://localhost",
                @"^https?://127\.0\.0\.1",
                @"^https?://10\.",
                @"^https?://172\.(1[6-9]|2[0-9]|3[01])\.",
                @"^https?://192\.168\.",
                @"^https?://169\.254\.",
                @"file://",
                @"ftp://",
                @"gopher://",
                @"dict://",
                @"ldap://"
            };

            return ssrfPatterns.Any(pattern => Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase));
        }

        private async Task<string> ReadRequestBody(HttpRequest request)
        {
            request.Body.Position = 0;
            using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            request.Body.Position = 0;
            return body;
        }

        private async Task LogSuspiciousActivity(HttpContext context, AttackDetectionResult attack, string clientIp)
        {
            var logEntry = new FirewallLogEntry
            {
                Timestamp = DateTime.UtcNow,
                ClientIp = clientIp,
                Method = context.Request.Method,
                Path = context.Request.Path,
                QueryString = context.Request.QueryString.ToString(),
                UserAgent = context.Request.Headers["User-Agent"].FirstOrDefault() ?? "",
                AttackType = attack.AttackType.ToString(),
                DetectedPattern = attack.DetectedPattern,
                Payload = attack.Payload,
                Action = _config.BlockMaliciousRequests ? "BLOCKED" : "LOGGED",
                Headers = context.Request.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
            };

            await _logService.LogAsync(logEntry);
        }

        private async Task BlockRequest(HttpContext context, string reason, string clientIp)
        {
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";

            var response = new
            {
                error = "Request blocked by firewall",
                reason = reason,
                timestamp = DateTime.UtcNow,
                clientIp = clientIp
            };

            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
        }

        private string GetClientIpAddress(HttpContext context)
        {
            return context.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim() ??
                   context.Request.Headers["X-Real-IP"].FirstOrDefault() ??
                   context.Connection.RemoteIpAddress?.ToString() ??
                   "unknown";
        }

        private Dictionary<AttackType, List<Regex>> InitializeAttackPatterns()
        {
            return new Dictionary<AttackType, List<Regex>>
            {
                [AttackType.XSS] = new List<Regex>
                {
                    new(@"<script[^>]*>.*?</script>", RegexOptions.IgnoreCase | RegexOptions.Singleline),
                    new(@"javascript:", RegexOptions.IgnoreCase),
                    new(@"on\w+\s*=", RegexOptions.IgnoreCase),
                    new(@"<iframe[^>]*>", RegexOptions.IgnoreCase),
                    new(@"<object[^>]*>", RegexOptions.IgnoreCase),
                    new(@"<embed[^>]*>", RegexOptions.IgnoreCase),
                    new(@"alert\s*\(", RegexOptions.IgnoreCase),
                    new(@"document\.", RegexOptions.IgnoreCase),
                    new(@"eval\s*\(", RegexOptions.IgnoreCase)
                },
                [AttackType.SQLi] = new List<Regex>
                {
                    new(@"(\'\s*(or|and)\s*\'\s*=\s*\')|(\'\s*(or|and)\s*\'.*?\')", RegexOptions.IgnoreCase),
                    new(@"union\s+select", RegexOptions.IgnoreCase),
                    new(@"drop\s+table", RegexOptions.IgnoreCase),
                    new(@"insert\s+into", RegexOptions.IgnoreCase),
                    new(@"delete\s+from", RegexOptions.IgnoreCase),
                    new(@"update\s+.*\s+set", RegexOptions.IgnoreCase),
                    new(@"exec\s*\(", RegexOptions.IgnoreCase),
                    new(@"(;|--|\#).*?(union|select|insert|update|delete|drop)", RegexOptions.IgnoreCase),
                    new(@"(benchmark|sleep|pg_sleep)\s*\(", RegexOptions.IgnoreCase)
                },
                [AttackType.LFI] = new List<Regex>
                {
                    new(@"\.\./", RegexOptions.IgnoreCase),
                    new(@"\.\.\\", RegexOptions.IgnoreCase),
                    new(@"/etc/passwd", RegexOptions.IgnoreCase),
                    new(@"/proc/", RegexOptions.IgnoreCase),
                    new(@"\\windows\\", RegexOptions.IgnoreCase),
                    new(@"file://", RegexOptions.IgnoreCase),
                    new(@"php://", RegexOptions.IgnoreCase)
                }
            };
        }
    }
}