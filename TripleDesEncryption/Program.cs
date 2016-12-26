using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Encryption;
using System.Security.Cryptography;


namespace TripleDesEncryption
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Press enter to start!");
            Console.ReadLine();
            Console.WriteLine("Started!");

            // Generating the key
            Random rnd = new Random();
            byte[] Key = new byte[16];
            rnd.NextBytes(Key);
            /*
            //Image testing
            Console.WriteLine("Loading Image {0}", Directory.GetCurrentDirectory() + "\\Pics" + "\\test1.jpg");
            Image img = Image.FromFile(Directory.GetCurrentDirectory() + "\\Pics" + "\\test1.jpg");
            Bitmap bmp = new Bitmap(img);
            
            Console.WriteLine("Encrypting the image (single-threaded)");
            var EncST = Stopwatch.StartNew();
            Bitmap EncryptedBmpS = ImageConverter.EncryptImg(bmp, Key, false);
            EncST.Stop();
            Console.WriteLine("Saving encrypted image (single-threaded) to: {0}", 
                                Directory.GetCurrentDirectory() + "\\Pics" + "\\EncryptedS.bmp");
            EncryptedBmpS.Save(Directory.GetCurrentDirectory() + "\\Pics" + "\\EncryptedS.bmp", ImageFormat.Bmp);

            Console.WriteLine("Decrypting the image (single-threaded)");
            var DecST = Stopwatch.StartNew();
            Bitmap DecryptedBmpS = ImageConverter.DecryptImg(EncryptedBmpS, Key, false);
            DecST.Stop(); 
            Console.WriteLine("Saving decrypted image (single-threaded) to: {0}",
                                 Directory.GetCurrentDirectory() + "\\Pics" + "\\DecryptedS.bmp");
            DecryptedBmpS.Save(Directory.GetCurrentDirectory() + "\\Pics" + "\\DecryptedS.bmp", ImageFormat.Bmp);

            
            Console.WriteLine("Encrypting the image (multi-threaded)");
            var EncMT = Stopwatch.StartNew();
            Bitmap EncryptedBmpM = ImageConverter.EncryptImg(bmp, Key, true);
            EncMT.Stop();
            Console.WriteLine("Saving encrypted image (multi-threaded) to: {0}",
                                Directory.GetCurrentDirectory() + "\\Pics" + "\\EncryptedM.bmp");
            EncryptedBmpM.Save(Directory.GetCurrentDirectory() + "\\Pics" + "\\EncryptedM.bmp", ImageFormat.Bmp);

            
            Console.WriteLine("Decrypting the image (multi-threaded)");
            var DecMT = Stopwatch.StartNew();
            Bitmap DecryptedBmpM = ImageConverter.DecryptImg(EncryptedBmpM, Key, true);
            DecMT.Stop();
            Console.WriteLine("Saving decrypted image (multi-threaded) to: {0}",
                                 Directory.GetCurrentDirectory() + "\\Pics" + "\\DecryptedM.bmp");
            DecryptedBmpM.Save(Directory.GetCurrentDirectory() + "\\Pics" + "\\DecryptedM.bmp", ImageFormat.Bmp);

            Console.WriteLine("Single - threaded Image Encyption: {0} milliseconds elapsed.", EncST.ElapsedMilliseconds);
            Console.WriteLine("Single - threaded Image Decyption: {0} milliseconds elapsed.", DecST.ElapsedMilliseconds);
            Console.WriteLine("Multi - threaded Image Encyption: {0} milliseconds elapsed.", EncMT.ElapsedMilliseconds);
            Console.WriteLine("Multi - threaded Image Decyption: {0} milliseconds elapsed.", DecMT.ElapsedMilliseconds);
            */

            // Text testing
            
            Console.WriteLine("Loading text {0}", Directory.GetCurrentDirectory() + "\\Text" + "\\test1.txt");
            byte[] TextData = File.ReadAllBytes(Directory.GetCurrentDirectory() + "\\Text" + "\\test1.txt");

            Encryption.TripleDES tDesS = new Encryption.TripleDES(TextData);
            tDesS.Key = Key;

            Console.WriteLine("Encrypting the text (single-threaded)");
            var EncSTTxt = Stopwatch.StartNew();
            byte[] EncTextDataS = tDesS.Encrypt(false);
            EncSTTxt.Stop();
            Console.WriteLine("Saving encrypted text (single-threaded) to: {0}",
                                Directory.GetCurrentDirectory() + "\\Text" + "\\EncryptedTextS.txt");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Text" + "\\EncryptedTextS.txt", EncTextDataS);

            Console.WriteLine("Decrypting the text (single-threaded)");
            var DecSTTxt = Stopwatch.StartNew();
            byte[] DecTextDataS = tDesS.Decrypt(false);
            DecSTTxt.Stop();
            Console.WriteLine("Saving decrypted text (single-threaded) to: {0}",
                                Directory.GetCurrentDirectory() + "\\Text" + "\\DecryptedTextS.txt");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Text" + "\\DecryptedTextS.txt", DecTextDataS);

            Encryption.TripleDES tDesM = new Encryption.TripleDES(TextData);
            tDesM.Key = Key;

            Console.WriteLine("Encrypting the text (multi-threaded)");
            var EncMTTxt = Stopwatch.StartNew();
            byte[] EncTextDataM = tDesM.Encrypt(true);
            EncMTTxt.Stop();
            Console.WriteLine("Saving encrypted text (multi-threaded) to: {0}",
                                Directory.GetCurrentDirectory() + "\\Text" + "\\EncryptedTextM.txt");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Text" + "\\EncryptedTextM.txt", EncTextDataM);

            Console.WriteLine("Decrypting the text (multi-threaded)");
            var DecMTTxt = Stopwatch.StartNew();
            byte[] DecTextDataM = tDesM.Decrypt(true);
            DecMTTxt.Stop();
            Console.WriteLine("Saving encrypted text (multi-threaded) to: {0}",
                                Directory.GetCurrentDirectory() + "\\Text" + "\\DecryptedTextM.txt");
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\Text" + "\\DecryptedTextM.txt", DecTextDataM);
           
            Console.WriteLine("Single - threaded Text Encyption: {0} milliseconds elapsed.", EncSTTxt.ElapsedMilliseconds);
            Console.WriteLine("Single - threaded Text Decyption: {0} milliseconds elapsed.", DecSTTxt.ElapsedMilliseconds);
            Console.WriteLine("Multi - threaded Text Encyption: {0} milliseconds elapsed.", EncMTTxt.ElapsedMilliseconds);
            Console.WriteLine("Multi - threaded Text Decyption: {0} milliseconds elapsed.", DecMTTxt.ElapsedMilliseconds);
            

            Console.WriteLine("Press enter to finish");
            Console.ReadLine();
        }

    }
}
