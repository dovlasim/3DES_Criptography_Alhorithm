using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Encryption
{
    /// <summary>
    /// Standard 1 layer of DES algorithm
    /// </summary>
    public static class DESEncryption
    {
        /// <summary>
        /// Encrypts all data within the list of Data Blocks
        /// </summary>
        /// <param name="Data">List of Data Blocks for encryption</param>
        /// <param name="info">All information needed for encryption</param>
        public static void DESEncrypt(List<DataBlock> Data, EncryptionInfo info)
        {
            BitArray Vector = info.InitVector;
            
            // Non-concurrent
            if(!info.Threaded)
            {
                for (int i = 0; i < Data.Count; i++)
                {
                    BitArray XordVal = Data.ElementAt(i).Data.Xor(Vector);
                    Data.ElementAt(i).Data = Algorithms.DES(XordVal, info.Key, false);
                    Vector = Data.ElementAt(i).Data;
                }
                return;
            }

            // Concurrent
            if(info.Encrypting)
            {
                // if part of the Encryption using Triple DES
                for (int i = 0; i < Data.Count; i++)
                {
                    Data.ElementAt(i).FirstSemaphore.WaitOne();
                    
                    BitArray XordVal = Data.ElementAt(i).Data.Xor(Vector);
                    Data.ElementAt(i).Data = Algorithms.DES(XordVal, info.Key, false);
                    Vector = Data.ElementAt(i).Data;

                    Data.ElementAt(i).SecondSemaphore.Release(1);
                }
            }else
            {
                // if part of the Decryption using Triple DES
                for (int i = 0; i < Data.Count; i++)
                {
                    Data.ElementAt(i).SecondSemaphore.WaitOne();
                    
                    BitArray XordVal = Data.ElementAt(i).Data.Xor(Vector);
                    Data.ElementAt(i).Data = Algorithms.DES(XordVal, info.Key, false);
                    Vector = Data.ElementAt(i).Data;

                    Data.ElementAt(i).ThirdSemaphore.Release(1);
                }
            }

        }

        /// <summary>
        /// Decrypts all data within the list of Data Blocks
        /// </summary>
        /// <param name="Data">List of Data Blocks for decryption</param>
        /// <param name="info">All information needed for decryption</param>
        public static void DESDecrypt(List<DataBlock> Data, EncryptionInfo info)
        {
            BitArray Vector;
            BitArray NotXordVal;

            // Non-Concurrent
            if(!info.Threaded)
            {
                Vector = Data.ElementAt(0).Data;
                NotXordVal = Algorithms.DES(Data.ElementAt(0).Data, info.Key, true);
                Data.ElementAt(0).Data = NotXordVal.Xor(info.InitVector);

                for (int i = 1; i < Data.Count; i++)
                {
                    BitArray TempVector = Data.ElementAt(i).Data;
                    NotXordVal = Algorithms.DES(Data.ElementAt(i).Data, info.Key, true);
                    Data.ElementAt(i).Data = NotXordVal.Xor(Vector);
                    Vector = TempVector;
                }
                return;
            }

            //Concurrent
            if(info.Encrypting)
            {
                // if part of the Encryption using Triple DES
                Data.ElementAt(0).SecondSemaphore.WaitOne();
                
                Vector = Data.ElementAt(0).Data;
                NotXordVal = Algorithms.DES(Data.ElementAt(0).Data, info.Key, true);
                Data.ElementAt(0).Data = NotXordVal.Xor(info.InitVector);

                Data.ElementAt(0).ThirdSemaphore.Release(1);

                for (int i = 1; i < Data.Count; i++)
                {
                    Data.ElementAt(i).SecondSemaphore.WaitOne();
                    
                    BitArray TempVector = Data.ElementAt(i).Data;
                    NotXordVal = Algorithms.DES(Data.ElementAt(i).Data, info.Key, true);
                    Data.ElementAt(i).Data = NotXordVal.Xor(Vector);
                    Vector = TempVector;

                    Data.ElementAt(i).ThirdSemaphore.Release(1);
                }

            }else
            {
                // if part of the Decryption using Triple DES
                Data.ElementAt(0).FirstSemaphore.WaitOne();
                
                Vector = Data.ElementAt(0).Data;
                NotXordVal = Algorithms.DES(Data.ElementAt(0).Data, info.Key, true);
                Data.ElementAt(0).Data = NotXordVal.Xor(info.InitVector);
                    
                Data.ElementAt(0).SecondSemaphore.Release(1);

                for (int i = 1; i < Data.Count; i++)
                {
                    Data.ElementAt(i).FirstSemaphore.WaitOne();
                    
                    BitArray TempVector = Data.ElementAt(i).Data;
                    NotXordVal = Algorithms.DES(Data.ElementAt(i).Data, info.Key, true);
                    Data.ElementAt(i).Data = NotXordVal.Xor(Vector);
                    Vector = TempVector;

                    Data.ElementAt(i).SecondSemaphore.Release(1);
                }
            }
        }

        // Same function as DESEncrypt (different semaphores), used for simplifying thread sync
        public static void DESEncryptScnd(List<DataBlock> Data, EncryptionInfo info)
        {
            BitArray Vector = info.InitVector;

            for (int i = 0; i < Data.Count; i++)
            {
                Data.ElementAt(i).ThirdSemaphore.WaitOne();
                
                BitArray XordVal = Data.ElementAt(i).Data.Xor(Vector);

                Data.ElementAt(i).Data = Algorithms.DES(XordVal, info.Key, false);
                Vector = Data.ElementAt(i).Data;

                Data.ElementAt(i).FirstSemaphore.Release(1);
            }
        }

        // Same function as DESDecrypt (different semaphores), used for simplifying thread sync
        public static void DESDecryptScnd(List<DataBlock> Data, EncryptionInfo info)
        {

            BitArray Vector;
            BitArray NotXordVal;

            Data.ElementAt(0).ThirdSemaphore.WaitOne();
            
            Vector = Data.ElementAt(0).Data;
            NotXordVal = Algorithms.DES(Data.ElementAt(0).Data, info.Key, true);
            Data.ElementAt(0).Data = NotXordVal.Xor(info.InitVector);

            Data.ElementAt(0).FirstSemaphore.Release(1);

            for (int i = 1; i < Data.Count; i++)
            {
                Data.ElementAt(i).ThirdSemaphore.WaitOne();
               
                BitArray TempVector = Data.ElementAt(i).Data;
                NotXordVal = Algorithms.DES(Data.ElementAt(i).Data, info.Key, true);
                Data.ElementAt(i).Data = NotXordVal.Xor(Vector);
                Vector = TempVector;

                Data.ElementAt(i).FirstSemaphore.Release(1);
            }
                
        }
    }
}
