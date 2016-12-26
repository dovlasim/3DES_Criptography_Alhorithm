using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;

namespace Encryption
{
    /// <summary>
    /// Class for wrapping all information about SBoxes of DES algorithm
    /// </summary>
    public class SBoxes
    {
        private BitArray[, ,] _values;
        private bool _initialized;

        public BitArray[, ,] Values
        {
            get { return _values; }
        }
        public bool Initialized
        {
            get { return _initialized; }
        }

        public SBoxes()
        {
            _values = new BitArray[8, 4, 16];
            _initialized = false;
           

            for(int i = 0; i < 8; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 16; k++ )
                    {
                        _values[i, j, k] = new BitArray(4);
                    }
                }
            }

        }

        /// <summary>
        /// Gets 1 of 8 SBoxes
        /// </summary>
        /// <param name="idx">Index of the wanted SBox</param>
        /// <returns>The wanted SBox</returns>
        public BitArray[,] GetSBox(int idx)
        {
            BitArray[,] SBox = new BitArray[4, 16];

            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 16; j++)
                {
                    SBox[i, j] = new BitArray(_values[idx, i, j]);
                }
            }

            return SBox;
        }
        
        /// <summary>
        /// Reads SBoxes in from a file
        /// </summary>
        public void ReadSBoxesFromFile()
        {
            string[] lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "\\Tables" + "\\SBoxes.txt");
            int BoxNum, RowNum, ColNum;
            BoxNum = 0;
            RowNum = 0;
            ColNum = 0;
            foreach(string line in lines)
            {
                ColNum = 0;

                string[] nums = line.Split(' ');
                foreach(string num in nums)
                {
                    int val = int.Parse(num);
                    _values[BoxNum, RowNum, ColNum] = IntTo4BitArray(val);
                    ColNum++;
                }

                RowNum++;
                if(RowNum % 4 == 0)
                {
                    BoxNum++;
                    RowNum = 0;
                }
            }

            _initialized = true;
        }

        /// <summary>
        /// Converts an integer to a 4 BitArray
        /// </summary>
        /// <param name="val">Integer to be converted</param>
        /// <returns>A converted 4 BitArray</returns>
        private BitArray IntTo4BitArray(int val)
        {
            BitArray RetVal = new BitArray(4);
           
            int i = 0;
            while(val != 0)
            {
                RetVal[3 - i] = (val % 2 == 1);
                i++;
                val /= 2;
            }

            return RetVal;
        }

    }
}
