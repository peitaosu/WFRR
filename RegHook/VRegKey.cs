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
        public Dictionary<string, VRegKey> Keys { set; get; }
        public List<VRegValue> Values { set; get; }
    }

    //virtual registry value
    public class VRegValue
    {
        public string Name { set; get; }
        public string Type { set; get; }
        public string Data { set; get; }
    }
}