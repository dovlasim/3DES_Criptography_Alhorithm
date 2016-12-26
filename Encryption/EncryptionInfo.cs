using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    /// <summary>
    /// Supplies the encryption/decryption process with all needed information
    /// </summary>
    public class EncryptionInfo
    {
        private BitArray _initVector;
        private BitArray _key;
        private bool _encrypting;
        private bool _threaded;

        public BitArray InitVector
        {
            get{return _initVector;}
            set{_initVector = value;}
        }

        public BitArray Key
        {
            get{return _key;}
            set{_key = value;}
        }

        public bool Encrypting
        {
            get { return _encrypting; }
            set { _encrypting = value; }
        }
        
        public bool Threaded
        {
            get { return _threaded; }
            set { _threaded = value; }
        }
        public EncryptionInfo()
        {
            _initVector = null;
            _key = null;
        }

        public EncryptionInfo(BitArray InitVector, BitArray Key, bool Encrypting, bool Threaded)
        {
            this._initVector = InitVector;
            this._key = Key;
            this._encrypting = Encrypting;
            this._threaded = Threaded;
        }
    }
}
