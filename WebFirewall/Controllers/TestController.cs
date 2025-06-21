using Microsoft.AspNetCore.Mvc;

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

        /// <summary>
        /// Endpoint de test basique
        /// </summary>
        [HttpGet("safe")]
        public IActionResult SafeEndpoint()
        {
            return Ok(new { message = "This is a safe endpoint", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint vulnérable pour tester XSS (sera bloqué par le firewall)
        /// </summary>
        [HttpGet("xss")]
        public IActionResult XssTest([FromQuery] string input = "")
        {
            // Cet endpoint est intentionnellement vulnérable pour tester le firewall
            return Ok(new { message = $"Input received: {input}", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint vulnérable pour tester SQL Injection
        /// </summary>
        [HttpPost("sqli")]
        public IActionResult SqliTest([FromBody] dynamic data)
        {
            // Cet endpoint simule une vulnérabilité SQL pour tester le firewall
            var query = data?.query?.ToString() ?? "";
            return Ok(new { message = $"Query would be: {query}", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint pour tester Local File Inclusion
        /// </summary>
        [HttpGet("lfi")]
        public IActionResult LfiTest([FromQuery] string file = "")
        {
            // Endpoint vulnérable pour tester LFI
            return Ok(new { message = $"File requested: {file}", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint pour tester SSRF
        /// </summary>
        [HttpGet("ssrf")]
        public IActionResult SsrfTest([FromQuery] string url = "")
        {
            // Endpoint vulnérable pour tester SSRF
            return Ok(new { message = $"URL requested: {url}", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint pour générer du trafic et tester le rate limiting
        /// </summary>
        [HttpGet("dos")]
        public IActionResult DosTest()
        {
            return Ok(new { message = "DoS test endpoint", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Endpoint avec upload de fichier pour tester différents vecteurs d'attaque
        /// </summary>
        [HttpPost("upload")]
        public async Task<IActionResult> UploadTest(IFormFile file)
        {
            if (file == null)
                return BadRequest("No file uploaded");

            using var reader = new StreamReader(file.OpenReadStream());
            var content = await reader.ReadToEndAsync();

            return Ok(new
            {
                filename = file.FileName,
                size = file.Length,
                contentPreview = content.Take(100),
                timestamp = DateTime.UtcNow
            });
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