using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;

namespace Encryption
{
    /// <summary>
    /// Class that combines 3 normal DES instances for more security
    /// </summary>
    public class TripleDES
    {
        private byte[] RawPrimalKey;
        private BitArray PrimalKey;
        private BitArray Key1;
        private BitArray Key2;
        private long RawDataLength;
        private BitArray InitVector1;
        private BitArray InitVector2;
        private BitArray InitVector3;
        List<DataBlock> DataBlocks;
        private bool _encrypted;

        public bool Encrypted
        {
            get { return _encrypted; }
        }

        public byte[] Key
        {
            get { return RawPrimalKey; }
            set 
            {
                RawPrimalKey = value;
                PrimalKey = BytesToBitArray(value);
                Key1 = Algorithms.GetLeftSubkey(PrimalKey);
                Key2 = Algorithms.GetRightSubkey(PrimalKey);
            }
        }


        public TripleDES(byte[] RawData)
        {
            RawDataLength = RawData.Length;

            // Splits data into 8 byte blocks and then converts 8 byte arrays into 64 BitArrays
            DataBlocks = BytesToBitArray(SplitData(RawData));

            Random rnd = new Random();


            // Initialization of Initial vectors for all three stages of Triple DES
            InitVector1 = new BitArray(64);
            InitVector2 = new BitArray(64);
            InitVector3 = new BitArray(64);

            for (int i = 0; i < 64; i++) 
            {
                InitVector1[i] = rnd.Next(0, 1) == 1;
                InitVector2[i] = rnd.Next(0, 1) == 1;
                InitVector3[i] = rnd.Next(0, 1) == 1;
            }


            _encrypted = false;
        }

       /// <summary>
       /// Combines three calls of normal DES algorithm for more security
       /// </summary>
        /// <param name="Threaded">Boolean value specifying whether encryption will be done concurrently</param>
       /// <returns>Byte array of encrypted data</returns>
        public byte[] Encrypt(bool Threaded)
        {
            //Initializing information needed for DES algorithm
            EncryptionInfo info1 = new EncryptionInfo(InitVector1, Key1, true, Threaded);
            EncryptionInfo info2 = new EncryptionInfo(InitVector2, Key2, true, Threaded);
            EncryptionInfo info3 = new EncryptionInfo(InitVector3, Key1, true, Threaded);

            if(Threaded)
            {
                //Initializing and starting threads (ENC - DEC - ENC)
                Thread Enc1 = new Thread(() => DESEncryption.DESEncrypt(DataBlocks, info1));
                Thread Dec = new Thread(() => DESEncryption.DESDecrypt(DataBlocks, info2));
                Thread Enc2 = new Thread(() => DESEncryption.DESEncryptScnd(DataBlocks, info3));

                Enc1.Start();
                Thread.Sleep(50);
                Dec.Start();
                Thread.Sleep(50);
                Enc2.Start();

                Enc1.Join();
                Dec.Join();
                Enc2.Join();
                Console.WriteLine("Multi - Threaded triple encryption done!");
            }else
            {
                // Non concurrent calls of ENC - DEC - ENC
                DESEncryption.DESEncrypt(DataBlocks, info1);
                DESEncryption.DESDecrypt(DataBlocks, info2);
                DESEncryption.DESEncrypt(DataBlocks, info3);
                Console.WriteLine("Single - Threaded triple encryption done!");
            }

            _encrypted = true;
            // Converts 64 BitArrays to 8 byte arrays and concatenates the byte arrays
            return ConcatData(BitArraytoBytes(DataBlocks));
        }

        /// <summary>
        /// Decrypts data that was encrypted using Triple DES
        /// </summary>
        /// <param name="Threaded">Boolean value specifying whether decryption will be done concurrently</param>
        /// <returns>Byte array of decrypted data</returns>
        public byte[] Decrypt(bool Threaded)
        {
            //Initializing information needed for DES algorithm
            EncryptionInfo info1 = new EncryptionInfo(InitVector3, Key1, false, Threaded);
            EncryptionInfo info2 = new EncryptionInfo(InitVector2, Key2, false, Threaded);
            EncryptionInfo info3 = new EncryptionInfo(InitVector1, Key1, false, Threaded);

            if(Threaded)
            {
                //Initializing and starting threads (DEC - ENC - DEC)
                Thread Dec1 = new Thread(() => DESEncryption.DESDecrypt(DataBlocks, info1));
                Thread Enc = new Thread(() => DESEncryption.DESEncrypt(DataBlocks, info2));
                Thread Dec2 = new Thread(() => DESEncryption.DESDecryptScnd(DataBlocks, info3));

                Dec1.Start();
                Thread.Sleep(50);
                Enc.Start();
                Thread.Sleep(50);
                Dec2.Start();

                Dec1.Join();
                Enc.Join();
                Dec2.Join();
                Console.WriteLine("Multi - Threaded triple decryption done!");
            }else
            {
                // Non concurrent calls of DEC - ENC - DEC
                DESEncryption.DESDecrypt(DataBlocks, info1);
                DESEncryption.DESEncrypt(DataBlocks, info2);
                DESEncryption.DESDecrypt(DataBlocks, info3);
                Console.WriteLine("Single - Threaded triple decryption done!");
            }

            _encrypted = false;
            // Converts 64 BitArrays to 8 byte arrays and concatenates the byte arrays
            return ConcatData(BitArraytoBytes(DataBlocks));
        }

        /// <summary>
        /// Converts an 8 byte array into a 64 BitArray
        /// </summary>
        /// <param name="Data">Byte array to be converted</param>
        /// <returns>Converted BitArray</returns>
        private BitArray BytesToBitArray(byte[] Data)
        {
            return new BitArray(Data);
        }

        /// <summary>
        /// Converts 64 BitArray into an 8 byte array
        /// </summary>
        /// <param name="Data">BitArray to be converted</param>
        /// <returns>Converted byte array</returns>
        private byte[] BitArraytoBytes(BitArray Data)
        {
            byte[] RetVal = new byte[Data.Length / 8];

            Data.CopyTo(RetVal, 0);
            return RetVal;
        }

        /// <summary>
        /// Converts a list of 8 byte arrays into a list of 64 BitArrays
        /// </summary>
        /// <param name="Data">List of byte arrays to be converted</param>
        /// <returns>Converted list of 64 BitArrays</returns>
        private List<DataBlock> BytesToBitArray(List<byte[]> Data)
        {
            List<DataBlock> RetVal = new List<DataBlock>();

            for (int i = 0; i < Data.Count; i++) 
            {
                RetVal.Add(new DataBlock(new BitArray(Data.ElementAt(i))));
            }

            return RetVal;
        }

        /// <summary>
        /// Converts a list of 64 BitArrays into a list of 8 byte arrays
        /// </summary>
        /// <param name="Data">List of 64 BitArrays</param>
        /// <returns>Converted list of 8 byte arrays</returns>
        private List<byte[]> BitArraytoBytes(List<DataBlock> Data)
        {
            List<byte[]> RetVal = new List<byte[]>();

            for (int i = 0; i < Data.Count; i++)
            {
                byte[] block = new byte[8];
                Data.ElementAt(i).Data.CopyTo(block, 0);
                RetVal.Add(block);
            }

            return RetVal;
        }

        /// <summary>
        /// Splits a byte array into a list of 8 byte blocks
        /// </summary>
        /// <param name="Data">Byte array to be split</param>
        /// <returns>List of 8 byte blocks</returns>
        private List<byte[]> SplitData(byte[] Data)
        {
            List<byte[]> RetVal = new List<byte[]>();
            long i;
            for (i = 0; i < RawDataLength - 8; i += 8)
            {
                byte[] block = new byte[8];
                
                for (int j = 0; j < 8; j++) 
                {
                    block[j] = Data[i + j];
                }
                RetVal.Add(block);
            }

            //Last Block doesnt have to be exactly 8 bytes long
            //but for purposes of DES, we make it 8 bytes long
            byte[] LastBlock = new byte[8];
            
            for(int j = 0; j < RawDataLength - i; j++)
            {
                LastBlock[j] = Data[i + j];
            }
            RetVal.Add(LastBlock);

            return RetVal;
        }

        /// <summary>
        /// Concatenates a list of 8 byte blocks into a byte array
        /// </summary>
        /// <param name="Data">List of 8 byte blocks</param>
        /// <returns>Concatenated byte array</returns>
        private byte[] ConcatData(List<byte[]> Data)
        {
            byte[] RetVal = new byte[RawDataLength];

            for (int i = 0; i < RawDataLength; i++)
            {
                RetVal[i] = (Data.ElementAt(i / 8))[i % 8];
            }

            return RetVal;
        }

    }
}
