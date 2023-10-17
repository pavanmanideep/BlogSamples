using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGP_EncryptionDecription
{
    public class Program
    {
        static void Main(string[] args)
        {
            try
            {
                #region Encrypt

                byte[] dataBytes = File.ReadAllBytes(@"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\Hi.txt");
                Stream keyIn = File.OpenRead(@"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\eHintsRPRMIntegrationKey_0x47F3A4D9_public.asc");
                Stream outStream = File.Create(@"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\Encrypted File\TestData.pgp");
                byte[] encrypted = PGPEncryptDecrypt.EncryptFile(dataBytes, "eHintsData", PGPEncryptDecrypt.ReadPublicKey(keyIn), false);
                outStream.Write(encrypted, 0, encrypted.Length);
                keyIn.Close();
                outStream.Close();

                #endregion

                #region Decrypt

                string inputFile = @"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\Encrypted File\TestData.pgp";
                string outputFile = @"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\Decrypted File\DecryptedTestData.txt";
                string privateKeyFile = @"C:\Users\Pavan.YARAGANI\Desktop\Keys\Final Test\eHints\eHintsRPRMIntegrationKey_0x47F3A4D9_SECRET.asc";
                string passPhrase = "eH(nT$5!ngHe@lthRprm*";
                PGPEncryptDecrypt.Decrypt(inputFile, privateKeyFile, passPhrase, outputFile);

                #endregion

            }
            catch (Exception ex)
            {
                throw new Exception("Exception occured during Encryption/Decryption");
            }
        }
    }
}
