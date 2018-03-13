
namespace Question1
{
    /**
     * Defines an object used for storing encryption keys
     * */
    class DecryptionKey
    {
        // The position in the cipher that this key applies to
        public int Position { get; set; }

        // The actual decryption key
        public int Key { get; set; }
    }
}
