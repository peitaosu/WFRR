import os, sys, json

def get_reg_str_list(reg_file_path):
    with open(reg_file_path) as reg_file:
        reg = reg_file.read().decode('utf-16').split('\r\n')
    return filter(None, reg)

def convert_reg_str_to_json(reg_str_list):
    reg_dict = {
        "Keys": {},
        "Values": []
    }
    for reg_str in reg_str_list:
        if reg_str == 'Windows Registry Editor Version 5.00':
            continue
        if reg_str.startswith('['):
            reg_str = reg_str[1:-1]
            cur_dict = reg_dict
            for reg_key in reg_str.split('\\'):
                reg_key = reg_key.lower()
                if reg_key not in cur_dict['Keys'].keys():
                    cur_dict['Keys'][reg_key] = {
                        "Keys": {},
                        "Values": []
                    }
                    cur_dict = cur_dict['Keys'][reg_key]
                else:
                    cur_dict = cur_dict['Keys'][reg_key]
            cur_key = cur_dict
        else:
            value_name = reg_str.split('=')[0].strip('"')
            value_content = reg_str.split('=')[1]
            if value_content.startswith('"'):
                value_type = "REG_SZ"
                value_data = value_content.strip('"')
            elif value_content.startswith('dword'):
                value_type = "REG_DWORD"
                value_data = value_content.split(':')[1]
            elif value_content.startswith('qword'):
                value_type = "REG_QWORD"
                value_data = value_content.split(':')[1]
            cur_key['Values'].append(
                {
                    "Name": value_name,
                    "Type": value_type,
                    "Data": value_data
                }
            )
    return reg_dict

def save_json_str_to_file(reg_dict, json_file_path):
    with open(json_file_path, 'w') as json_file:
        json.dump(reg_dict, json_file)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print 'Usage: python Reg2JSON.py in.reg out.json'
    else:
        reg = get_reg_str_list(sys.argv[1])
        reg_dict = convert_reg_str_to_json(reg)
        save_json_str_to_file(reg_dict, sys.argv[2])
