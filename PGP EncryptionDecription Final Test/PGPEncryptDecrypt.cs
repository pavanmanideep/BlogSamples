using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Linq;

namespace PGP_EncryptionDecription
{
    public static class PGPEncryptDecrypt
    {
       
        public static void EncryptFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            try
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
                {
                    PgpPublicKey encKey = ReadPublicKey(publicKeyStream);

                    using (MemoryStream bOut = new MemoryStream())
                    {
                        PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                        PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(inputFile));

                        comData.Close();
                        PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                        cPk.AddMethod(encKey);
                        byte[] bytes = bOut.ToArray();

                        using (Stream outputStream = File.Create(outputFile))
                        {
                            if (armor)
                            {
                                using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                                {
                                    using (Stream cOut = cPk.Open(armoredStream, bytes.Length))
                                    {
                                        cOut.Write(bytes, 0, bytes.Length);
                                    }
                                }
                            }
                            else
                            {
                                using (Stream cOut = cPk.Open(outputStream, bytes.Length))
                                {
                                    cOut.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                    }
                }
            }
            catch (PgpException e)
            {
                throw;
            }
        }



        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            
            // Just loop through the collection till we find a key suitable for encryption, then iterate through the key rings.   

         foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                    {
                        return k;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }


        public static byte[] EncryptFile(byte[] clearData, string fileName, PgpPublicKey encKey, bool withIntegrityCheck)
        {

            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // To Generate compressed data.             
            Stream pOut = lData.Open(
                cos,                    // the compressed output stream
                PgpLiteralData.Binary,
                fileName,               // "filename" to store
                clearData.Length,       // length of clear data
                DateTime.UtcNow         // current time
            );

            pOut.Write(clearData, 0, clearData.Length);

            lData.Close();
            comData.Close();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, new SecureRandom());

            cPk.AddMethod(encKey);

            byte[] bytes = bOut.ToArray();

            MemoryStream encOut = new MemoryStream();
            Stream os = encOut;

            Stream cOut = cPk.Open(os, bytes.Length);
            cOut.Write(bytes, 0, bytes.Length);  // obtain the actual bytes from the compressed stream
            cOut.Close();

            encOut.Close();

            return encOut.ToArray();
        }

        public static void Decrypt(string inputfile, string privateKeyFile, string passPhrase, string outputFile)
        {
            using (Stream inputStream = File.OpenRead(inputfile))
            {
                using (Stream keyIn = File.OpenRead(privateKeyFile))
                {
                    Decrypt(inputStream, keyIn, passPhrase, outputFile);
                }
            }
        }

        public static Stream GenerateStreamFromString(string str)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(str);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
        public static void DecryptString(string inputfile, string privateKey, string passPhrase, string outputFile)
        {
            using (Stream inputStream = File.OpenRead(inputfile))
            {
                using (Stream keyIn = GenerateStreamFromString(privateKey))
                {
                    Decrypt(inputStream, keyIn, passPhrase, outputFile);
                }
            }
        }

        public static void Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
        {
            try
            {
                PgpObjectFactory pgpF = null;
                PgpEncryptedDataList enc = null;
                PgpObject o = null;
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = null;

                pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                // find secret key 
                pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpF != null)
                    o = pgpF.NextPgpObject();

                // the first object might be a PGP marker packet. 
                if (o is PgpEncryptedDataList)
                    enc = (PgpEncryptedDataList)o;
                else
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                // decrypt 
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                    throw new ArgumentException("Secret key for message not found.");

                PgpObjectFactory plainFact = null;

                using (Stream clear = pbe.GetDataStream(sKey))
                {
                    plainFact = new PgpObjectFactory(clear);


                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData)
                    {
                        PgpCompressedData cData = (PgpCompressedData)message;
                        PgpObjectFactory of = null;

                        using (Stream compDataIn = cData.GetDataStream())
                        {
                            of = new PgpObjectFactory(compDataIn);
                            message = of.NextPgpObject();
                        }


                        if (message is PgpOnePassSignatureList)
                        {
                            message = of.NextPgpObject();
                            PgpLiteralData Ld = null;
                            Ld = (PgpLiteralData)message;
                            using (Stream output = File.Create(outputFile))
                            {
                                Stream unc = Ld.GetInputStream();
                                Streams.PipeAll(unc, output);
                            }
                        }
                        else
                        {
                            PgpLiteralData Ld = null;
                            Ld = (PgpLiteralData)message;
                            using (Stream output = File.Create(outputFile))
                            {
                                Stream unc = Ld.GetInputStream();
                                Streams.PipeAll(unc, output);
                            }
                        }
                    }
                    else if (message is PgpLiteralData)
                    {
                        PgpLiteralData ld = (PgpLiteralData)message;
                        string outFileName = ld.FileName;

                        using (Stream fOut = File.Create(outputFile))
                        {
                            Stream unc = ld.GetInputStream();
                            Streams.PipeAll(unc, fOut);
                        }
                    }
                    else if (message is PgpOnePassSignatureList)
                        throw new PgpException("Encrypted message contains a signed message - not literal data.");
                    else
                        throw new PgpException("Message is not a simple encrypted file - type unknown.");

                }
            }
            catch (PgpException ex)
            {
                throw;
            }

        }

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }
    }
}