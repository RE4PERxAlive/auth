using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization; // Reference System.Web.Extensions in .NET Framework 4.7.2
using System.Windows.Forms; // Reference System.Windows.Forms for GUI popup dialogs

namespace BloodyAuthSystem
{
    /// <summary>
    /// Bloody Auth Desktop Client Guard for C# .NET Framework 4.7.2 (EXE or DLL)
    /// Performs first-run System UUID & HWID validation against Bloody Auth server.
    /// </summary>
    public class BloodyAuthGuard
    {
        // -------------------------------------------------------------------------
        // CONFIGURATION - Bloody Auth Server Credentials
        // -------------------------------------------------------------------------
        public static string OwnerId { get; set; } = "e4b3c2a1-8765-4321-90ab-cdef12345678";
        public static string SecretKey { get; set; } = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a";
        public static string ApiUrl { get; set; } = "https://bloody-auth.api/v1/verify_uuid";

        private static readonly HttpClient client = new HttpClient();

        #region First-Run Authorization Check

        /// <summary>
        /// Validates System Hardware UUID on first run.
        /// If system UUID matches registered UUID in Bloody Auth -> Returns TRUE & begins execution.
        /// If system UUID fails or is revoked -> Displays 'authorization failed' dialog and returns FALSE.
        /// </summary>
        /// <param name="registeredUserUuid">The registered User UUID key</param>
        /// <returns>True if system UUID is authorized, False otherwise</returns>
        public static async Task<bool> CheckFirstRunAuthorizationAsync(string registeredUserUuid)
        {
            string systemUuid = GetLocalSystemUUID();

            var requestBody = new
            {
                owner_id = OwnerId,
                secret_key = SecretKey,
                user_uuid = registeredUserUuid,
                system_uuid = systemUuid,
                machine_name = Environment.MachineName,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string json = serializer.Serialize(requestBody);
            StringContent content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                HttpResponseMessage response = await client.PostAsync(ApiUrl, content);
                string responseText = await response.Content.ReadAsStringAsync();

                dynamic result = serializer.Deserialize<dynamic>(responseText);

                if (result != null && result.ContainsKey("success") && (bool)result["success"] == true)
                {
                    // System UUID matched & registered! Proceed with execution
                    return true;
                }
            }
            catch
            {
                // Network error or server unreachable
            }

            // Authorization Failed handling
            MessageBox.Show(
                "authorization failed", 
                "Bloody Auth System", 
                MessageBoxButtons.OK, 
                MessageBoxIcon.Error
            );

            return false;
        }

        /// <summary>
        /// Synchronous wrapper for non-async DLL entry points
        /// </summary>
        public static bool CheckFirstRunAuthorization(string registeredUserUuid)
        {
            return Task.Run(() => CheckFirstRunAuthorizationAsync(registeredUserUuid)).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Generates deterministic System Hardware UUID based on system signature
        /// </summary>
        public static string GetLocalSystemUUID()
        {
            string rawFingerprint = string.Format("{0}_{1}_{2}",
                Environment.MachineName,
                Environment.UserName,
                Environment.ProcessorCount);

            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(rawFingerprint));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash) sb.Append(b.ToString("X2"));
                return "UUID-" + sb.ToString().Substring(0, 20);
            }
        }

        #endregion
    }

    // =========================================================================
    // OPTION A: INTEGRATION FOR C# EXECUTABLE (.EXE)
    // =========================================================================
    internal class ProgramExeExample
    {
        [STAThread]
        static async Task Main(string[] args)
        {
            string userKey = "UUID-8F9A-4C2E-90B1"; // System UUID key assigned to client

            Console.WriteLine("[+] Checking System UUID authorization...");
            bool isAuthorized = await BloodyAuthGuard.CheckFirstRunAuthorizationAsync(userKey);

            if (!isAuthorized)
            {
                // System UUID match failed -> Terminate application immediately
                Environment.Exit(0);
                return;
            }

            // System UUID authorized! Proceed to launch app
            MessageBox.Show("Authorization successful! Launching main application.", "Bloody Auth", MessageBoxButtons.OK, MessageBoxIcon.Information);
            
            // Launch main application window:
            // Application.Run(new MainForm());
        }
    }

    // =========================================================================
    // OPTION B: INTEGRATION FOR C# CLASS LIBRARY (.DLL)
    // =========================================================================
    public class DllMainEntry
    {
        /// <summary>
        /// DLL Entry method invoked on first run
        /// </summary>
        public static bool InitializeDll(string userKey)
        {
            bool isAuthorized = BloodyAuthGuard.CheckFirstRunAuthorization(userKey);
            if (!isAuthorized)
            {
                // Authorization failed -> Return false & abort DLL payload execution
                return false;
            }

            // Authorization passed -> Begin DLL payload logic
            ExecuteDllFeatures();
            return true;
        }

        private static void ExecuteDllFeatures()
        {
            // Place your protected DLL functionality here
        }
    }
}
