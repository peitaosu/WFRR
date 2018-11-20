import os, sys, json, optparse

def get_reg_str_list(reg_file_path):
    # suppose the input file using utf-16 because it"s default encoding of regedit exported file
    try:
        with open(reg_file_path) as reg_file:    
            return reg_file.read().decode("utf-16").replace("\\\r\n  ", "").split("\r\n")
    except:
        with open(reg_file_path, encoding="utf-16") as reg_file:
            return reg_file.read().replace("\\\r\n  ", "").split("\r\n")

def get_vreg_config(config):
    with open(config) as in_file:
        return json.load(in_file)

def parse_to_reg(reg_str_list, config, out_reg, is32bit):
    if is32bit:
        if "WOW6432Node" not in config["VRegRedirected"]:
            print("[ERROR]: You application is 32bit application but your registry items are not redirected to Software\\WOW6432Node.")
            print("         Please make sure your registry items will be redirected to Software\\WOW6432Node.")
            sys.exit()
    with open(out_reg, "w") as out_file:
        for reg_str in reg_str_list:
            if reg_str.startswith("["):
                out_file.write("[{}\\{}\n".format(config["VRegRedirected"], reg_str[1:]))
            else:
                out_file.write(reg_str + "\n")

def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--in", dest="in_reg", default=None,
                      help="*.reg file to input")  
    parser.add_option("-o", "--out", dest="out_reg", default="out.reg",
                      help="*.reg file to output")  
    parser.add_option("-c", "--cfg", dest="config", default="V_REG.json",
                      help="V_REG.json to input")
    parser.add_option("--32bit", dest="is32bit", action="store_true", default=False,
                      help="is your application 32bit?")
    (options, args) = parser.parse_args()
    if not options.in_reg or not os.path.isfile(options.config):
        parser.print_help()
        sys.exit()
    return options


if __name__ == "__main__":
    options = get_options()
    reg = get_reg_str_list(options.in_reg)
    cfg = get_vreg_config(options.config)
    parse_to_reg(reg, cfg, options.out_reg, options.is32bit)
