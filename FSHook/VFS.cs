using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSHook
{
    //virtual file system
    public class VFS
    {
        public List<VFSMapping> Mapping { set; get; }
    }

    //virtual file system mapping
    public class VFSMapping
    {
        public string Source { set; get; }
        public string Destination { set; get; }
    }
}