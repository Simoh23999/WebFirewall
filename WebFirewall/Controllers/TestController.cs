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

        /// <summary>
        /// Endpoint de test basique
        /// </summary>        
        [HttpGet("safe")]
        public IActionResult SafeEndpoint()
        {
            return Ok(new { message = "This is a safe endpoint", timestamp = DateTime.UtcNow.AddHours(1) });
        }



        /// <summary>
        /// Endpoint vulnérable pour tester XSS,input dans l'URL
        /// </summary>
        /// <remarks>
        /// Exemple d’appel :
        ///
        ///     GET /api/test/xss?input=%3Cscript%3Ealert('xss')%3C/script%3E
        ///
        /// </remarks>
        /// <param name="input">Exemple : &lt;script&gt;alert('test')&lt;/script&gt;</param>

        [HttpGet("xss")]
        public IActionResult XssTest([FromQuery] string input = "")
        {
            return Ok(new { message = $"Input received: {input}", timestamp = DateTime.UtcNow.AddHours(1) });
        }



        /// <summary>
        /// Endpoint pour tester SQL Injection (requête dans le corps JSON)
        /// </summary>
        /// <remarks>
        /// Exemple d’appel :
        ///
        ///     POST /api/test/sqli
        ///     Body : { "query": "' OR 1=1 --" }
        ///
        /// </remarks>
        /// <param name="data">Objet JSON contenant une clé "query"</param>
        /// <returns>Message avec la requête</returns>
        [HttpPost("sqli")]
        public IActionResult SqliTest([FromBody] JsonElement data)
        {
            string query = "";
            if (data.TryGetProperty("query", out JsonElement queryElement))
            {
                query = queryElement.GetString();
            }
            return Ok(new { message = $"Query would be: {query}", timestamp = DateTime.UtcNow.AddHours(1) });
        }


        /// Endpoint pour tester Local File Inclusion (DIrectory traversal)   
        /// <summary>
        /// Test de Directory Traversal (LFI)
        /// </summary>
        /// <remarks>
        /// Exemple d’appel :
        ///
        ///     GET /api/test/lfi?file=../../../etc/passwd
        ///
        /// </remarks>
        /// <param name="file">Exemple : ../../../etc/passwd</param>
        /// <returns>Message avec le nom de fichier</returns>
        [HttpGet("lfi")]
        public IActionResult LfiTest([FromQuery] string file = "")
        {
            // Endpoint vulnérable pour tester LFI
            return Ok(new { message = $"File requested: {file}", timestamp = DateTime.UtcNow.AddHours(1) });
        }


        /// Endpoint pour tester SSRF      
        /// <summary>
        /// Test SSRF
        /// </summary>
        /// <remarks>
        /// Exemple d’appel :
        ///
        ///     GET /api/test/ssrf?url=http://localhost:8080/admin
        ///
        /// </remarks>
        /// <param name="url">Exemple : http://localhost:8080/admin</param>
        /// <returns>Message avec l'URL demandée</returns>
        [HttpGet("ssrf")]
        public IActionResult SsrfTest([FromQuery] string url = "")
        {
            // Endpoint vulnérable pour tester SSRF
            return Ok(new { message = $"URL requested: {url}", timestamp = DateTime.UtcNow.AddHours(1) });
        }


        /// Endpoint pour générer du trafic et tester le rate limiting  
        /// <summary>
        /// Test pour simuler un DoS 
        /// </summary>
        /// <returns>Message pour test de charge</returns>
        [HttpGet("dos")]
        public IActionResult DosTest()
        {
            return Ok(new { message = "DoS test endpoint", timestamp = DateTime.UtcNow.AddHours(1) });
        }


        /// <summary>
        /// Génère des exemples de test 
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
                timestamp = DateTime.UtcNow.AddHours(1)
            });
        }
    }
}