using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace WebFirewall.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        
        /// Endpoint de test basique        
        [HttpGet("safe")]
        public IActionResult SafeEndpoint()
        {
            return Ok(new { message = "This is a safe endpoint", timestamp = DateTime.UtcNow });
        }

        
        /// Endpoint vulnérable pour tester XSS (sera bloqué par le firewall)        
        [HttpGet("xss")]
        public IActionResult XssTest([FromQuery] string input = "")
        {
            return Ok(new { message = $"Input received: {input}", timestamp = DateTime.UtcNow });
        }

        
        /// Endpoint vulnérable pour tester SQL Injection        
        [HttpPost("sqli")]
        public IActionResult SqliTest([FromBody] JsonElement data)
        {
            string query = "";
            if (data.TryGetProperty("query", out JsonElement queryElement))
            {
                query = queryElement.GetString();
            }
            return Ok(new { message = $"Query would be: {query}", timestamp = DateTime.UtcNow });
        }

        
        /// Endpoint pour tester Local File Inclusion (DIrectory traversal)   
        [HttpGet("lfi")]
        public IActionResult LfiTest([FromQuery] string file = "")
        {
            // Endpoint vulnérable pour tester LFI
            return Ok(new { message = $"File requested: {file}", timestamp = DateTime.UtcNow });
        }

        
        /// Endpoint pour tester SSRF        
        [HttpGet("ssrf")]
        public IActionResult SsrfTest([FromQuery] string url = "")
        {
            // Endpoint vulnérable pour tester SSRF
            return Ok(new { message = $"URL requested: {url}", timestamp = DateTime.UtcNow });
        }

        
        /// Endpoint pour générer du trafic et tester le rate limiting        
        [HttpGet("dos")]
        public IActionResult DosTest()
        {
            return Ok(new { message = "DoS test endpoint", timestamp = DateTime.UtcNow });
        }


        /// <summary>
        /// Génère des requêtes de test automatiques
        /// </summary>
        [HttpGet("generate-attacks")]
        public IActionResult GenerateTestAttacks()
        {
            var attacks = new[]
            {
                "/api/test/xss?input=<script>alert('xss')</script>",
                "/api/test/lfi?file=../../../etc/passwd",
                "/api/test/ssrf?url=http://localhost:8080/admin",
                "/api/test/sqli (POST with body: {\"query\": \"' OR 1=1--\"})"
            };

            return Ok(new
            {
                message = "Test attack URLs generated",
                attacks = attacks,
                note = "These URLs will trigger the firewall when accessed",
                timestamp = DateTime.UtcNow
            });
        }
    }
}