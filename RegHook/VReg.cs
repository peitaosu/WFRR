using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RegHook
{
    //virtual registry key
    public class VRegKey
    {
        public List<VRegKeyMapping> Mapping { set; get; }
        //virtual registry root
        public string VRegRedirected { set; get; }
    }

    //virtual registry key mapping
    public class VRegKeyMapping
    {
        public string Source { set; get; }
        public string Destination { set; get; }
    }
}