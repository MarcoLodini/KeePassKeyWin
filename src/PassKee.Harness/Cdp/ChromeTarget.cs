using System;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace PassKee.Harness.Cdp
{
    /// <summary>
    /// Discovers the CDP WebSocket URL for an open Chrome tab via the /json endpoint.
    /// </summary>
    public static class ChromeTarget
    {
        /// <summary>
        /// Returns the webSocketDebuggerUrl for the first page target at the given debugging port.
        /// Throws if Chrome is not reachable or has no page targets.
        /// </summary>
        public static async Task<string> GetFirstPageWebSocketUrlAsync(int port = 9222)
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var json = await http.GetStringAsync($"http://localhost:{port}/json");
            var targets = JArray.Parse(json);

            foreach (var target in targets)
            {
                if (target["type"]?.Value<string>() == "page")
                {
                    var url = target["webSocketDebuggerUrl"]?.Value<string>();
                    if (!string.IsNullOrEmpty(url))
                        return url;
                }
            }

            throw new InvalidOperationException(
                $"No page targets found at http://localhost:{port}/json. " +
                "Make sure Chrome is running with --remote-debugging-port=" + port);
        }
    }
}
