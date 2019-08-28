using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordHash
{
    class Program
    {
        static void Main(string[] args)
        {
            var hasher = new PasswordHasher();
            var hash = hasher.HashPassword("ClearTextPassword");
            Console.WriteLine(hash);
            Console.ReadLine();
        }
    }
}
