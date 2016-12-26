using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Encryption
{
    /// <summary>
    /// Static class used for main DES algorithm and its helper functions
    /// </summary>
    public static class Algorithms
    {
        // static tables used in DES algorithm
        private static int[,] EBitSelectionTable = null;
        private static SBoxes _SBoxes = null;
        private static int[,] PBoxPermutationTable = null;
        private static int[] KeyShiftingTable = null;
        private static int[] DecryptingKeyShiftingTable = null;
        private static int[] KeyContractionPermutationTable = null;
        private static int[] InitialPermutationTable = null;
        private static int[] ReversePermutationTable = null;
        
        /// <summary>
        /// Main DES function (64 bit --> 64 bit)
        /// </summary>
        /// <param name="DataBlock">64 BitArray to be processed using DES algorithm</param>
        /// <param name="Key">64 Bit Key used in the process</param>
        /// <param name="Decrypting">Boolean value specifying whether its a encryption or decryption process</param>
        /// <returns>Encrypted or decrypted 64 BitArray</returns>
        public static BitArray DES(BitArray DataBlock, BitArray Key, bool Decrypting)
        {
            //Reads all tables from respective files
            CreateTables();

            // All tables initialized?
            if(EBitSelectionTable == null || !_SBoxes.Initialized || PBoxPermutationTable == null
                || KeyShiftingTable == null || KeyContractionPermutationTable == null 
                || InitialPermutationTable == null || ReversePermutationTable == null)
            {
                return null;
            }

            // 1st step - Initial permutation
            DataBlock = InitialPermutation(DataBlock);
            
            // Removes insignificant bits of the key (64 bits --> 56 bits)
            Key = RemoveParityBits(Key);

            // Splits 64 BitArray data block into 2x 32 BitArrays
            BitArray LeftDataBlock = GetLeftDataBlock(DataBlock);
            BitArray RightDataBlock = GetRightDataBlock(DataBlock);

            //Feistel rounds
            for (int RoundIdx = 0; RoundIdx < 16; RoundIdx++ )
            {
                // Splits the 56 BitArray Key into 2x 28 BitArray subkeys
                BitArray LeftSubkey = GetLeftSubkey(Key);
                BitArray RightSubkey = GetRightSubkey(Key);

                // Shifts the subkeys based on which feistel round is it and whether its encrypting or decrypting
                LeftSubkey = GetShiftedRoundSubkey(LeftSubkey, RoundIdx, Decrypting);
                RightSubkey = GetShiftedRoundSubkey(RightSubkey, RoundIdx, Decrypting);

                // Concatenates the shifted subkeys (value will be used as next rounds key)
                Key = ConcatSubkeys(LeftSubkey, RightSubkey);
                
                // Does contraction permutation to the key
                BitArray RoundSubkey = KeyContractionPermutation(Key);

                // Left data block XOR FeistelFunc
                BitArray XordVal = LeftDataBlock.Xor(FeistelFunction(RightDataBlock, RoundSubkey));

                // Updates left and right data block values
                LeftDataBlock = RightDataBlock;
                RightDataBlock = XordVal;
            }

            // Concatenates Right and Left data blocks in that order
            DataBlock = ConcatDataBlocks(RightDataBlock, LeftDataBlock);

            // (Initial permutation)^(-1)
            DataBlock = ReversePermutation(DataBlock);

            return DataBlock;
        }

        /// <summary>
        /// Does initial permutation of a 64 BitArray using InitialPermutation table (64bit --> 64 bit)
        /// </summary>
        /// <param name="Data">64 BitArray</param>
        /// <returns>Permutated 64 BitArray of data</returns>
        private static BitArray InitialPermutation(BitArray Data)
        {
            BitArray RetVal = new BitArray(64);

            for (int i = 0; i < 64; i++)
            {
                RetVal[i] = Data[InitialPermutationTable[i] - 1];
            }

            return RetVal;
        }

        /// <summary>
        /// Does inverse operation of initial permutation using ReversePermutation table (64bit --> 64 bit)
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        private static BitArray ReversePermutation(BitArray Data)
        {
            BitArray RetVal = new BitArray(64);

            for (int i = 0; i < 64; i++)
            {
                RetVal[i] = Data[ReversePermutationTable[i] - 1];
            }

            return RetVal;
        }
        
        /// <summary>
        /// Removes parity (insignificant) bit of the key (64 bit -> 56 bit)
        /// </summary>
        /// <param name="Key">64 BitArray key</param>
        /// <returns>56 BitArray key</returns>
        private static BitArray RemoveParityBits(BitArray Key)
        {
            BitArray RetVal = new BitArray(56);

            int cnt = 0;
            for (int i = 1; i <= Key.Length; i++)
            {
                if (i % 8 == 0)
                {
                    continue;
                }
                RetVal[cnt] = Key[i - 1];
                cnt++;
            }

            return RetVal;
        }

        /// <summary>
        /// Gets only the first 32 Bits of the 64 BitArray (64 bit --> 32 bit)
        /// </summary>
        /// <param name="Data">64 BitArray</param>
        /// <returns>Left 32 BitArray</returns>
        private static BitArray GetLeftDataBlock(BitArray Data)
        {
            BitArray RetVal = new BitArray(32);

            for (int i = 0; i < 32; i++)
            {
                RetVal[i] = Data[i];
            }

            return RetVal;
        }

        /// <summary>
        /// Gets only the second 32 Bits of the 64 BitArray (64 bit --> 32 bit)
        /// </summary>
        /// <param name="Data">64 BitArray</param>
        /// <returns>Right 32 BitArray</returns>
        private static BitArray GetRightDataBlock(BitArray Data)
        {
            BitArray RetVal = new BitArray(32);

            for (int i = 0; i < 32; i++)
            {
                RetVal[i] = Data[i + 32];
            }

            return RetVal;
        }

        /// <summary>
        /// Gets only the first half of the Key
        /// </summary>
        /// <param name="Key">Key to be used in the extraction</param>
        /// <returns>Left half of the Key</returns>
        public static BitArray GetLeftSubkey(BitArray Key)
        {
            BitArray RetVal = new BitArray(Key.Length / 2);

            for (int i = 0; i < Key.Length / 2; i++)
            {
                RetVal[i] = Key[i];
            }

            return RetVal;
        }

        /// <summary>
        /// Gets only the second half of the Key
        /// </summary>
        /// <param name="Key">Key to be used in the extraction</param>
        /// <returns>Right half of the Key</returns>
        public static BitArray GetRightSubkey(BitArray Key)
        {
            BitArray RetVal = new BitArray(Key.Length / 2);

            for (int i = Key.Length / 2; i < Key.Length; i++)
            {
                RetVal[i - Key.Length / 2] = Key[i];
            }

            return RetVal;
        }

        /// <summary>
        /// Concatenates two subkeys
        /// </summary>
        /// <param name="LeftSubkey">Used as first half of the newly generated key</param>
        /// <param name="RightSubkey">Used as second half of the newly generated key</param>
        /// <returns>Concatenated key</returns>
        private static BitArray ConcatSubkeys(BitArray LeftSubkey, BitArray RightSubkey)
        {
            BitArray RetVal = new BitArray(LeftSubkey.Length + RightSubkey.Length);

            for (int i = 0; i < LeftSubkey.Length + RightSubkey.Length; i++)
            {
                if (i < LeftSubkey.Length)
                {
                    RetVal[i] = LeftSubkey[i];
                    continue;
                }
                RetVal[i] = RightSubkey[i - LeftSubkey.Length];
            }

            return RetVal;
        }

        /// <summary>
        /// Concatenates two 32 bit data blocks
        /// </summary>
        /// <param name="LeftDataBlock">Used as first half of the newly generated data block</param>
        /// <param name="RightDataBlock">Used as second half of the newly generated data block</param>
        /// <returns>Concatenated 64 bit data block</returns>
        private static BitArray ConcatDataBlocks(BitArray LeftDataBlock, BitArray RightDataBlock)
        {
            BitArray RetVal = new BitArray(64);

            for (int i = 0; i < 64; i++ )
            {
                if(i < 32)
                {
                    RetVal[i] = LeftDataBlock[i];
                    continue;
                }

                RetVal[i] = RightDataBlock[i - 32];
            }

            return RetVal;
        }

        /// <summary>
        /// Gets the shifted version of a given subkey based on the current feistel round and
        /// whether its a encryption or decryption process
        /// </summary>
        /// <param name="Subkey">Subkey used for deriving the shifted subkey</param>
        /// <param name="Round">Feistel round index</param>
        /// <param name="Decrypting">Boolean value specifying whether its a encryption or decryption process</param>
        /// <returns>Shifted subkey</returns>
        private static BitArray GetShiftedRoundSubkey(BitArray Subkey, int Round, bool Decrypting)
        {
            
            BitArray RetVal = new BitArray(Subkey.Length);
            if(Decrypting)
            {
                // if its decryption, we are using DecryptingKeyShifting table and shifting to the right
                int NumForShift = DecryptingKeyShiftingTable[Round];
                for (int i = 0; i < Subkey.Length; i++)
                {
                    RetVal[(i + NumForShift) % Subkey.Length] = Subkey[i];
                }
            }else
            {
                // if its encryption, we are using KeyShifting table and shifting to the left
                int NumForShift = KeyShiftingTable[Round];
                for (int i = 0; i < Subkey.Length; i++)
                {
                    RetVal[i] = Subkey[(i + NumForShift) % Subkey.Length];
                }
            }

            return RetVal;
        }

        /// <summary>
        /// Gets the contracted and permutated version of the key using KeyContractionPermutation table
        /// (56 bit --> 48 bit)
        /// </summary>
        /// <param name="Key">Key used for deriving the new key</param>
        /// <returns>Contracted and permutated key</returns>
        private static BitArray KeyContractionPermutation(BitArray Key)
        {
            BitArray RetVal = new BitArray(48);

            for(int i = 0; i < 48; i++)
            {
                RetVal[i] = Key[KeyContractionPermutationTable[i] - 1];
            }

            return RetVal;
        }

        /// <summary>
        /// Gets the value of Feistel function based on the data and the key
        /// </summary>
        /// <param name="Data">Data used in Feistel function</param>
        /// <param name="Key">Key used in Feistel function</param>
        /// <returns>Data after the transformation using Feistel function</returns>
        private static BitArray FeistelFunction(BitArray Data, BitArray Key)
        {
            // We expand the data from 32 bits to 48 bits
            BitArray ExpandedData = ExpansionPermutation(Data);

            // Expanded data XOR Key
            BitArray XordData = ExpandedData.Xor(Key);

            // We do SBox substitution of data that was xor-ed
            // and we do PBox permutation over the result of SBox substitution
            return PBoxPermutation(SBoxSubstitution(XordData));
        }

        /// <summary>
        /// Expands the Data using EBitSelection table (32 bit --> 48 bit)
        /// </summary>
        /// <param name="Data">32 BitArray to be expanded</param>
        /// <returns>Expanded 48 BitArray</returns>
        private static BitArray ExpansionPermutation(BitArray Data)
        {
            BitArray RetVal = new BitArray(48);

            for (int i = 0; i < 48; i++)
            {
                RetVal[i] = Data[EBitSelectionTable[i / 6, i % 6] - 1];
            }

            return RetVal;
        }

        /// <summary>
        /// Does SBox substitution using an instance of SBoxes class (48 bit --> 32 bit)
        /// </summary>
        /// <param name="Data">Data which will be used in SBox substitution</param>
        /// <returns>Value of Data after SBox substitution</returns>
        private static BitArray SBoxSubstitution(BitArray Data)
        {
            BitArray RetVal = new BitArray(32);

            // Going through all eight SBoxes
            for (int i = 0; i < 8; i++)
            {
                // Finding Row and column indices
                BitArray RowBits = new BitArray(2);
                BitArray ColBits = new BitArray(4);
                
                // First and last bit are used for determining Row index
                RowBits[0] = Data[6 * i];
                RowBits[1] = Data[6 * i + 5];

                // Rest 4 bits are used for determining Column index
                ColBits[0] = Data[6 * i + 1];
                ColBits[1] = Data[6 * i + 2];
                ColBits[2] = Data[6 * i + 3];
                ColBits[3] = Data[6 * i + 4];

                int RowIdx = 0;
                int ColIdx = 0;

                // Binary --> Decimal
                for (int j = 0; j < RowBits.Length; j++) 
                {
                    if(RowBits[j])
                    {
                        RowIdx += Convert.ToInt32(Math.Pow(2, j));
                    }
                }

                for(int j = 0; j < ColBits.Length; j++)
                {
                    if(ColBits[j])
                    {
                        ColIdx += Convert.ToInt32(Math.Pow(2, j));
                    }
                }

                // Construction return value
                BitArray SCell = (_SBoxes.GetSBox(i))[RowIdx, ColIdx];
                for (int j = 0; j < SCell.Length; j++)
                {
                    RetVal[i * SCell.Length + j] = SCell[j];
                }
            }

            return RetVal;
        }

        /// <summary>
        /// Does PBox permutation using PBoxPermutation table (32 bit --> 32 bit)
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        private static BitArray PBoxPermutation(BitArray Data)
        {
            BitArray RetVal = new BitArray(32);

            for (int i = 0; i < 32; i++)
            {
                RetVal[i] = Data[PBoxPermutationTable[i / 4, i % 4] - 1];
            }

            return RetVal;
        }

        /// <summary>
        /// Initializes the tables
        /// </summary>
        private static void CreateTables()
        {
            if (EBitSelectionTable == null)
            {
                EBitSelectionTable = ReadEBitSelectionTableFromFile();
            }

            if (_SBoxes == null)
            {
                _SBoxes = new SBoxes();
                _SBoxes.ReadSBoxesFromFile();
            }

            if (PBoxPermutationTable == null)
            {
                PBoxPermutationTable = ReadPBoxPermutationTableFromFile();
            }

            if (KeyShiftingTable == null)
            {
                KeyShiftingTable = ReadKeyShiftingTableFromFile();
            }

            if(DecryptingKeyShiftingTable == null)
            {
                DecryptingKeyShiftingTable = ReadDecryptingKeyShiftingTableFromFile();
            }

            if (KeyContractionPermutationTable == null)
            {
                KeyContractionPermutationTable = ReadKeyContractionPermutationTableFromFile();
            }

            if(InitialPermutationTable == null)
            {

                InitialPermutationTable = ReadInitialPermutationTableFromFile();
            }

            if(ReversePermutationTable == null)
            {
                ReversePermutationTable = ReadReversePermutationTableFromFile();
            }

        }

        /// <summary>
        /// Reads ReversePermutation table from a text file (1 x 64)
        /// </summary>
        /// <returns>ReversePermutation table</returns>
        private static int[] ReadReversePermutationTableFromFile()
        {
            try
            {
                int[] RetVal = new int[64];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\RevPermTable.txt");
            
                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get Reverse permutation table. error: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Reads InitialPermutation table for a text file (1 x 64)
        /// </summary>
        /// <returns>InitialPermutation table</returns>
        private static int[] ReadInitialPermutationTableFromFile()
        {
            try
            {
                int[] RetVal = new int[64];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\InitPermTable.txt");
            
                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get Initial permutation table. error: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Reads KeyContractionPermutation table from a text file (1 x 48)
        /// </summary>
        /// <returns>KeyContractionPermutation table</returns>
        private static int[] ReadKeyContractionPermutationTableFromFile()
        {
            try
            {
                int[] RetVal = new int[48];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\KeyContPermTable.txt");

                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get Key contraction permutation table. error: {0}", e.Message);
                return null;
            }

        }

        /// <summary>
        /// Reads KeyShifting table from a text file (1 x 16)
        /// </summary>
        /// <returns>KeyShifting table</returns>
        private static int[] ReadKeyShiftingTableFromFile()
        {
            try
            {
                int[] RetVal = new int[16];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\KeyShiftingTable.txt");

                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get Key shifting table. error: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Reads DecryptingKeyShifting table from a text file (1 x 16)
        /// </summary>
        /// <returns>DecryptingKeyShifting table</returns>
        private static int[] ReadDecryptingKeyShiftingTableFromFile()
        {
            try
            {
                int[] RetVal = new int[16];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\DecrKeyShiftingTable.txt");

                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get Key shifting table. error: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Reads PBoxPermutation table from a text file (8 x 4)
        /// </summary>
        /// <returns>PBoxPermutation table</returns>
        private static int[,] ReadPBoxPermutationTableFromFile()
        {
            try
            {
                int[,] RetVal = new int[8, 4];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\PBoxPermTable.txt");

                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i / 4, i % 4] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get PBox permutation table. error: {0}", e.Message);
                return null;
            }
        }

        /// <summary>
        /// Reads EBitSelection table from a text file (8 x 6)
        /// </summary>
        /// <returns>EBitSelection table</returns>
        private static int[,] ReadEBitSelectionTableFromFile()
        {
            try
            {
                int[,] RetVal = new int[8, 6];
                string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\EBitSelecttable.txt");

                int i = 0;
                foreach (string line in lines)
                {
                    string[] nums = line.Split(' ');
                    foreach (string num in nums)
                    {
                        RetVal[i / 6, i % 6] = int.Parse(num);
                        i++;
                    }
                }

                return RetVal;
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to get EBit selection table table. error: {0}", e.Message);
                return null;
            }
        }

    }
}
