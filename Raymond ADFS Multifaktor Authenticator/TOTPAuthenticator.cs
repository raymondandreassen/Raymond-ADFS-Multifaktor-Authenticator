using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Data.SqlClient;

namespace Raymond.ADFS_MFA
{
    public class TOTPAuthenticator
    {
        private const string allowedCharacters      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // Due to Base32 encoding; https://code.google.com/p/vellum/wiki/GoogleAuthenticator
        private static int validityPeriodSeconds    = 30; // RFC6238 4.1; X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
        private static int futureIntervals          = 1; // How much time in the future can the client be; in validityPeriodSeconds intervals.
        private static int pastIntervals            = 1; // How much time in the past can the client be; in validityPeriodSeconds intervals.
        private static int secretKeyLength          = 16; // Must be a multiple of 8, iPhones accept up to 16 characters (apparently; didn't test it; don't own an iPhone)
        private static readonly DateTime unixEpoch  = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // Beginning of time, according to Unix
        private const string sqlConnectString       = "server=SQL-02.ad.uit.no;initial catalog=TOTPAuthentication;integrated security=true;";


        public static string GenerateSecretKey()
        {
            Random random = new Random((int)DateTime.Now.Ticks & 0x0000FFFF);
            return new string((new char[secretKeyLength]).Select(c => c = allowedCharacters[random.Next(0, allowedCharacters.Length)]).ToArray());
        }

        private static long GetInterval(DateTime dateTime)
        {
            TimeSpan elapsedTime = dateTime.ToUniversalTime() - unixEpoch;
            return (long)elapsedTime.TotalSeconds / validityPeriodSeconds;
        }

        public static string GetCode(string secretKey)
        {
            return GetCode(secretKey, DateTime.Now);
        }

        public static string GetCode(string secretKey, DateTime when)
        {
            return GetCode(secretKey, GetInterval(when));
        }

        private static string GetCode(string secretKey, long timeIndex)
        {
            var secretKeyBytes = Base32Encode(secretKey);
            //for (int i = secretKey.Length; i < secretKeyBytes.Length; i++) {secretKeyBytes[i] = 0;}
            HMACSHA1 hmac = new HMACSHA1(secretKeyBytes);
            byte[] challenge = BitConverter.GetBytes(timeIndex);
            if (BitConverter.IsLittleEndian) Array.Reverse(challenge);
            byte[] hash = hmac.ComputeHash(challenge);
            int offset = hash[19] & 0xf;
            int truncatedHash = hash[offset] & 0x7f;
            for (int i = 1; i < 4; i++)
            {
                truncatedHash <<= 8;
                truncatedHash |= hash[offset + i] & 0xff;
            }
            truncatedHash %= 1000000;
            return truncatedHash.ToString("D6");
        }

        public static bool CheckCodeByKey(string secretKey, string code)
        {
            return CheckCode(secretKey, code, DateTime.Now);
        }

        private static bool CheckCode(string secretKey, string code, DateTime when)
        {
            long currentInterval = GetInterval(when);
            bool success = false;
            for (long timeIndex = currentInterval - pastIntervals; timeIndex <= currentInterval + futureIntervals; timeIndex++)
            {
                string intervalCode = GetCode(secretKey, timeIndex);
                bool intervalCodeHasBeenUsed = false;// CodeIsUsed(upn, timeIndex);
                if (ConstantTimeEquals(intervalCode, code) && !intervalCodeHasBeenUsed)
                {
                    success = true;
                    // todo: add code here that adds the code for the user to codes used during an interval.
                    break;
                }
            }
            return success;
        }

        public static bool CheckCode(string upn, string code)
        {
            string secretKey = GetSecretKey(upn);
            return CheckCode(secretKey, code, upn, DateTime.Now);
        }

        private static bool CheckCode(string secretKey, string code, string upn, DateTime when)
        {
            long currentInterval = GetInterval(when);
            bool success = false;
            for (long timeIndex = currentInterval - pastIntervals; timeIndex <= currentInterval + futureIntervals; timeIndex++)
            {
                string intervalCode = GetCode(secretKey, timeIndex);
                bool intervalCodeHasBeenUsed = CodeIsUsed(upn, timeIndex);
                if (!intervalCodeHasBeenUsed && ConstantTimeEquals(intervalCode, code))
                {
                    success = true;
                    SetUsedCode(upn, timeIndex);
                    break;
                }
            }
            return success;
        }
        private static byte[] Base32Encode(string source)
        {
            var bits = source.ToUpper().ToCharArray().Select(c => Convert.ToString(allowedCharacters.IndexOf(c), 2).PadLeft(5, '0')).Aggregate((a, b) => a + b);
            return Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
        }
        protected static bool ConstantTimeEquals(string a, string b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;

            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)a[i] ^ (uint)b[i];
            }

            return diff == 0;
        }

        public static string GetSecretKey(string upn)
        {
            string result = null;
            using (SqlConnection sqlConnection = new SqlConnection(sqlConnectString))
            {
                string sqlCommandString = "SELECT secret FROM Secrets WHERE upn = @upn";
                SqlCommand sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                object oResult = sqlCommand.ExecuteScalar();
                result = (string)oResult;
            }
            return result;
        }

        public static void SetSecretKey(string upn, string secret)
        {
            using (SqlConnection sqlConnection = new SqlConnection(sqlConnectString))
            {
                string sqlCommandString = "INSERT INTO Secrets (upn, secret) VALUES (@upn, @secret)";
                SqlCommand sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@secret", secret);
                sqlCommand.ExecuteNonQuery();
            }
        }

        private static bool CodeIsUsed(string upn, long interval)
        {
            bool result;
            using (SqlConnection sqlConnection = new SqlConnection(sqlConnectString))
            {
                string sqlCommandString = "SELECT COUNT(*) FROM UsedCodes WHERE upn = @upn AND interval = @interval";
                SqlCommand sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", interval);
                int count = (int)sqlCommand.ExecuteScalar();
                result = (count > 0);

                // Housekeeping
                sqlCommandString = "DELETE FROM UsedCodes WHERE upn = @upn AND interval < @interval";
                sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", interval - (pastIntervals * 2));
                sqlCommand.ExecuteNonQuery();
            }
            return result;
        }

        private static void SetUsedCode(string upn, long interval)
        {
            using (SqlConnection sqlConnection = new SqlConnection(sqlConnectString))
            {
                string sqlCommandString = "INSERT INTO UsedCodes (upn, interval) VALUES (@upn, @interval)";
                SqlCommand sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", interval);
                sqlCommand.ExecuteNonQuery();
            }
        }
    }
}
