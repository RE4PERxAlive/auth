using System;
using System.IO;
using System.Net;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SimpleAuth
{
    public static class Auth
    {
        // =========================================================================
        // CONFIGURATION - Bloody Auth Server Credentials
        // =========================================================================
        public static string ApiUrl    = "http://127.0.0.1:8080/verify";
        public static string OwnerId   = "e4b3c2a1-8765-4321-90ab-cdef12345678";
        public static string SecretKey = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a";

        // =========================================================================
        // MAIN VERIFICATION CALL
        // Usage in Main(): if (!Auth.Verify()) return;
        // =========================================================================
        public static bool Verify()
        {
            string reason = "Cannot connect to Auth Server (is server running?)";
            string systemUuid = GetSystemUUID();

            try
            {
                string url = $"{ApiUrl}?owner_id={Uri.EscapeUriString(OwnerId)}&secret_key={Uri.EscapeUriString(SecretKey)}&system_uuid={Uri.EscapeUriString(systemUuid)}";
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                request.Timeout = 6000;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                {
                    string reply = reader.ReadToEnd().Trim();

                    if (reply.Contains("\"status\":1") || reply.Contains("\"status\": 1"))
                    {
                        return true;
                    }
                    else
                    {
                        int idx = reply.IndexOf("\"message\":\"");
                        if (idx != -1)
                        {
                            int start = idx + 11;
                            int end = reply.IndexOf("\"", start);
                            if (end != -1) reason = reply.Substring(start, end - start);
                        }
                        else
                        {
                            reason = "System UUID is not authorized";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                reason = "Network error: " + ex.Message;
            }

            MessageBox.Show($"authorization failed\n\nSystem UUID: {systemUuid}\nReason: {reason}", "Bloody Auth Guard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }

        // Retrieves Windows System Hardware UUID
        public static string GetSystemUUID()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        string val = obj["UUID"]?.ToString();
                        if (!string.IsNullOrEmpty(val)) return val.Trim();
                    }
                }
            }
            catch { }

            return Environment.MachineName;
        }
    }
}
