using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSHook
{
    //virtual directory
    public class VDirectory
    {
        public Dictionary<string, VDirectory> Dirs { set; get; }
        public List<VFile> Files { set; get; }
    }

    //virtual file
    public class VFile
    {
        public string Name { set; get; }
        public string Size { set; get; }
    }
}