using System;
using System.IO;
using NitroxClient.Persistence.Model;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using LitJson;
using System.Security.Cryptography;

namespace NitroxClient.Persistence
{
    public static class PersistedClientData
    {
        private static PersistedClientDataModel model = null;

        private const string FILE_NAME = ".\\client.json";

        private static byte[] key = new Byte[16];
        private static byte[] iv = new Byte[16];
        private static bool needsKey = true;

        private static void CheckKeySingleton()
        {
            if (needsKey == true)
            {
                string userId = PlatformUtils.main.GetCurrentUserId();
                Random prng = new Random((int)Convert.ToInt64(userId)); //Only tested on Steam.
                prng.NextBytes(key);
                prng.NextBytes(iv);
                needsKey = false;
            }
        }

        private static void Persist()
        {
            string output = JsonMapper.ToJson(model);
#if RELEASE
            CheckKeySingleton();
            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(output);
                        }
                        output = Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
#endif
            File.WriteAllText(FILE_NAME, output);
        }

        private static string DecryptJSON(string json)
        {
#if RELEASE
            CheckKeySingleton();
            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(json)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
#endif
            return json;
        }

        private static void CheckSingleton()
        {
            if (model == null)
            {
                string text = File.ReadAllText(FILE_NAME);
                model = JsonMapper.ToObject<PersistedClientDataModel>(DecryptJSON(text));
            }
        }

        public static Guid GetToken(string ip, string port)
        {
            CheckSingleton();
            foreach (SavedServer pair in model.SavedServers)
            {
                if (pair.Ip.Equals(ip) && pair.Port.Equals(port)) //Always use trusted members to the left a .Equals call. Don't compare potentially unsafe data; assume parameters might be null.
                {
                    return new Guid(pair.Token);
                }
            }
            return Guid.Empty;
        }

        public static void EmplaceServer(string name, string ip, string port, Guid token)
        {
            CheckSingleton();
            SavedServer savedServer = new SavedServer() { Name = name, Ip = ip, Port = port, Token = token.ToString() };
            if(GetToken(savedServer.Ip, savedServer.Port) != Guid.Empty) //Some validation is better than no validation.
            {
                throw new Exception($"Failed to add '{ip}':'{port}' because there is already an entry for it.");
            }
            model.SavedServers.Add(savedServer);
            Persist();
        }

        public static List<SavedServer> GetServers()
        {
            CheckSingleton();
            return model.SavedServers;
        }

        public static void InitalizeServerList()
        {
            if (!File.Exists(FILE_NAME))
            {
                model = new PersistedClientDataModel();
                //Remove this regression scenario in later releases.
                if(File.Exists(".\\servers"))
                {
                    using (StreamReader sr = new StreamReader(".\\servers"))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            string[] lineData = line.Split('|');
                            string serverName = lineData[0];
                            string serverIp = lineData[1];
                            string serverPort;
                            if (lineData.Length == 3)
                            {
                                serverPort = lineData[2];
                            }
                            else
                            {
                                Match match = Regex.Match(serverIp, @"^(.*?)(?::(\d{3,5}))?$");
                                serverIp = match.Groups[1].Value;
                                serverPort = match.Groups[2].Success ? match.Groups[2].Value : "11000";
                            }
                            model.SavedServers.Add(new SavedServer() { Name = serverName, Ip = serverIp, Port = serverPort, Token = Guid.NewGuid().ToString() });
                        }
                    }
                    File.Delete(".\\servers");
                }
                else
                {
                    model.SavedServers.Add(new SavedServer() { Name = "local server", Ip = "127.0.0.1", Port = "11000", Token = Guid.NewGuid().ToString() });
                }
                Persist();
            }
        }

        public static void RemoveServerByIndex(int index)
        {
            CheckSingleton();
            if(model.SavedServers.Count > index)
            {
                model.SavedServers.RemoveAt(index);
                Persist();
            }
        }
    }
}
