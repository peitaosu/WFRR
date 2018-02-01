using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RegHook
{
    public class VRegKey
    {
        public Dictionary<string, VRegKey> Keys { set; get; }
        public List<VRegValue> Values { set; get; }
    }

    public class VRegValue
    {
        public string Name { set; get; }
        public string Type { set; get; }
        public string Data { set; get; }
    }
}
