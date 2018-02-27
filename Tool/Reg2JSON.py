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
                if reg_key not in cur_dict['Keys'].keys():
                    cur_dict['Keys'][reg_key] = {
                        "Keys": {},
                        "Values": []
                    }
                    cur_dict = cur_dict['Keys'][reg_key]
                else:
                    cur_dict = cur_dict['Keys'][reg_key]
        else:
            continue
    return reg_dict

def save_json_str_to_file(reg_dict, json_file_path):
    with open(json_file_path, 'w') as json_file:
        json.dump(reg_dict, json_file)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print 'Please provide reg file.'
    else:
        reg = get_reg_str_list(sys.argv[1])
        reg_dict = convert_reg_str_to_json(reg)
        save_json_str_to_file(reg_dict, sys.argv[2])
