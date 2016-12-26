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
    /// Class used for wrapping 64 BitArray and semaphores for thread sync 
    /// </summary>
    public class DataBlock
    {
        private Semaphore _first;
        private Semaphore _second;
        private Semaphore _third;
        private BitArray _data;

        public Semaphore FirstSemaphore
        {
            get { return _first; }
            set { _first = value; }
        }

        public Semaphore SecondSemaphore
        {
            get { return _second; }
            set { _second = value; }
        }

        public Semaphore ThirdSemaphore
        {
            get { return _third; }
            set { _third = value; }
        }

        public BitArray Data
        {
            get { return _data; }
            set { _data = value; }
        }


        public DataBlock(BitArray Data)
        {
            this.Data = Data;

            // Only first semaphore has intial value 1 - (Thread that should process data first uses it)
            FirstSemaphore = new Semaphore(1, 1);
            SecondSemaphore = new Semaphore(0, 1);
            ThirdSemaphore = new Semaphore(0, 1);
        }
    }
}
