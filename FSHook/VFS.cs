using System.Collections.Generic;

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