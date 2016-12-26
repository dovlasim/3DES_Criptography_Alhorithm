using System;
using System.IO;
using System.Drawing;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Encryption;

namespace TripleDesEncryption
{
    /// <summary>
    /// Static class used to "encapsulate" image preparation and encryption or decryption
    /// </summary>
    public static class ImageConverter
    {
        /// <summary>
        /// Encrypts BitmapData of a Bitmap object
        /// </summary>
        /// <param name="bmp">Bitmap object whose data will be encrypted</param>
        /// <param name="Key">Key which will be used in the encryption process</param>
        /// <param name="Threaded">Boolean value specifying whether encryption will be done concurrently</param>
        /// <returns>Bitmap object with encrypted content data</returns>
        public static Bitmap EncryptImg(Bitmap bmp, byte[] Key, bool Threaded)
        {

            // Create a new bitmap.
            // Lock the bitmap's bits.  
            Rectangle rect = new Rectangle(0, 0, bmp.Width, bmp.Height);
            System.Drawing.Imaging.BitmapData bmpData =
                bmp.LockBits(rect, System.Drawing.Imaging.ImageLockMode.ReadWrite,
                bmp.PixelFormat);

            
            // Get the address of the first line.
            IntPtr ptr = bmpData.Scan0;

            // Declare an array to hold the bytes of the bitmap.
            int bytes  = Math.Abs(bmpData.Stride) * bmp.Height;
             byte[] rgbValues = new byte[bytes];

            // Copy the RGB values into the array.
            System.Runtime.InteropServices.Marshal.Copy(ptr, rgbValues, 0, bytes);

            Encryption.TripleDES Encryption = new Encryption.TripleDES(rgbValues);
            Encryption.Key = Key;
            rgbValues = Encryption.Encrypt(Threaded);

            // Copy the RGB values back to the bitmap
            System.Runtime.InteropServices.Marshal.Copy(rgbValues, 0, ptr, bytes);

            // Unlock the bits.
            bmp.UnlockBits(bmpData);

            return bmp;
        }

        /// <summary>
        /// Decrypts BitmapData of a Bitmap object
        /// </summary>
        /// <param name="bmp">Bitmap object whose data will be decrypted</param>
        /// <param name="Key">Key which will be used in the decryption process</param>
        /// <param name="Threaded">Boolean value specifying whether decryption will be done concurrently</param>
        /// <returns>Bitmap object with decrypted content data</returns>
        public static Bitmap DecryptImg(Bitmap bmp, byte[] Key, bool Threaded)
        {
            // Create a new bitmap.
            // Lock the bitmap's bits.  
            Rectangle rect = new Rectangle(0, 0, bmp.Width, bmp.Height);
            System.Drawing.Imaging.BitmapData bmpData =
                bmp.LockBits(rect, System.Drawing.Imaging.ImageLockMode.ReadWrite,
                bmp.PixelFormat);

            // Get the address of the first line.
            IntPtr ptr = bmpData.Scan0;

            // Declare an array to hold the bytes of the bitmap.
            int bytes = Math.Abs(bmpData.Stride) * bmp.Height;
            byte[] rgbValues = new byte[bytes];

            // Copy the RGB values into the array.
            System.Runtime.InteropServices.Marshal.Copy(ptr, rgbValues, 0, bytes);

            Encryption.TripleDES Encryption = new Encryption.TripleDES(rgbValues);
            Encryption.Key = Key;
            rgbValues = Encryption.Decrypt(Threaded);

            // Copy the RGB values back to the bitmap
            System.Runtime.InteropServices.Marshal.Copy(rgbValues, 0, ptr, bytes);

            // Unlock the bits.
            bmp.UnlockBits(bmpData);

            return bmp;
        }

        
    }
}
