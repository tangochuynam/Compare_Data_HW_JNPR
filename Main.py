import os
import re
import datetime
import pandas as pd
import sys
time_df = datetime.datetime(2017, 10, 1, 18, 15, 0, 0)


# some thing go wrong

class L2_Circuit:
    def __init__(self, vc_state='', ac_interface='', neighbor='', vc_id=''):
        self.vc_state = vc_state
        self.ac_interface = ac_interface
        self.neighbor = neighbor
        self.vc_id = vc_id

class VPLS:
    vpls_instance = ''

    def __init__(self, vc_state='', neighbor='', vc_id=''):
        self.vc_state = vc_state
        self.neighbor = neighbor
        self.vc_id = vc_id


class Utils:
    @staticmethod
    def find_index_to_split(pattern):
        lst_index = []
        for i in range(0, len(pattern)):
            e = pattern[i]
            if e == '+':
                lst_index.append(i)
        return lst_index

    @staticmethod
    def split_line(lst_index, line):
        lst_col = []
        num_col = len(lst_index)
        for i in range(0, num_col):
            if i < num_col - 1:
                start = lst_index[i]
                end = lst_index[i + 1]
                col = line[start:end].strip()
                lst_col.append(col)
            if i == num_col - 1:
                index = lst_index[i]
                col = line[index:].strip()
                lst_col.append(col)
        return lst_col

    @staticmethod
    def split_data_by_command(pttr, data):
        part = re.findall(pttr, data, flags=re.MULTILINE)
        return part

    @staticmethod
    def convert_mac_to_jnpr_form(mac):
        la = mac.split('-')
        lb = list(map(lambda x: (x[0:2] + ':' + x[2:]).lower(), la))
        return ':'.join(lb)

    @staticmethod
    def get_diff_lst_mac_hw_jnpr(lst_mac_hw, lst_mac_jnpr):
        set_hw = set(lst_mac_hw)
        set_jnpr = set(lst_mac_jnpr)
        diff = set_hw.difference(set_jnpr)
        if diff == set():
            return ''
        else:
            return ', '.join(list(diff))

    @staticmethod
    def get_info_part_1_huawei(part_1):
        lst_l2vc = []
        pttr_1 = ' *Client Interface .*\n(?: (?:[^*](?!Client Interface)).*\n)+'
        lst_cli_int = re.findall(pttr_1, part_1, flags=re.MULTILINE)
        for cli_int in lst_cli_int:
            l2_vc = L2_Circuit()
            lines = cli_int.split('\n')
            for line in lines:
                if line.strip() != '':
                    tmp = line.strip().split(':')
                    tmp[0] = tmp[0].strip()
                    tmp[1] = tmp[1].strip()
                    if tmp[0] == 'Client Interface':
                        l2_vc.ac_interface = tmp[1]
                    if tmp[0] == 'VC State':
                        l2_vc.vc_state = tmp[1]
                    if tmp[0] == 'VC ID':
                        l2_vc.vc_id = tmp[1]
                    if tmp[0] == 'Destination':
                        l2_vc.neighbor = tmp[1]
            lst_l2vc.append((l2_vc.vc_state, l2_vc.ac_interface, l2_vc.neighbor, int(l2_vc.vc_id)))
        # create DataFrame from lst_l2vc
        labels = ['VC State', 'AC Interface', 'Neighbor', 'VC ID']
        df_l2vc = pd.DataFrame.from_records(lst_l2vc, columns=labels)
        #df_l2vc.sort_values(['Neighbor', 'VC ID'], ascending=[True, True])
        return df_l2vc

    @staticmethod
    def get_info_part_2_huawei(part_2):
        lst_vsi_store = []
        pttr_2 = 'VSI Name.*\n(?:(?!VSI Name).*\n)+'
        pttr_2_sub = '(?:(?:\d+.){3}\d+).*\n(?:(?!(?:\d+.){3}\d+).*\n)*'
        lst_vsi = re.findall(pttr_2, part_2, flags=re.MULTILINE)
        for vsi in lst_vsi:
            lines = vsi.split('\n')
            VPLS.vpls_instance = lines[0].split()[2].strip()
            lst_peer = re.findall(pttr_2_sub, vsi, flags=re.MULTILINE)
            for peer in lst_peer:
                vpls = VPLS()
                cols = peer.split()
                vpls.neighbor, vpls.vc_id , vpls.vc_state = cols[0], cols[1], cols[4]
                lst_vsi_store.append((vpls.vc_state, vpls.vpls_instance, vpls.neighbor, vpls.vc_id))
        labels = ['VC State', 'VPLS Instance', 'Neighbor', 'VC ID']
        df_vsi = pd.DataFrame.from_records(lst_vsi_store, columns=labels)
        #df_vsi.sort_values(['Neighbor', 'VC ID'], ascending=[True, True])
        return df_vsi


    @staticmethod
    def get_info_part_3_huawei(part_3):
        dict_general = {}
        pttr_3 = 'MAC Address:.*\n(?:(?!MAC Address:).*\n)+'
        labels = ['VSI', 'HW AC-remote IP', 'mac-count', 'List-Mac']
        labels_sum = ['VSI', 'VSI Mac-Count', 'List-Mac']
        lst_mac_add = re.findall(pttr_3, part_3, flags=re.MULTILINE)
        for mac_dd in lst_mac_add:
            lines = mac_dd.split('\n')
            # just consider line[0] - mac address, line[1] - port, line[3]- peer ip
            line_mac = ''
            line_port = ''
            line_peer = ''

            for line in lines:
                if line.startswith('MAC Address'):
                    line_mac = line
                if line.startswith('Port'):
                    line_port = line
                if line.startswith('Peer IP'):
                    line_peer = line
            index_vsi = line_mac.find('VLAN/VSI/SI')
            mac_tmp = line_mac[:index_vsi].split(':')[1].strip()
            mac = Utils.convert_mac_to_jnpr_form(mac_tmp)
            key = line_mac[index_vsi:].split(':')[1].strip()
            index_type = line_port.find('Type')
            port_key = line_port[:index_type].split(':')[1].strip()

            if port_key.startswith('Tun'):
                index_vc_id = line_peer.find('VC-ID')
                peer_ip = line_peer[:index_vc_id].split(':')[1].strip()
                port_key = peer_ip

            if key not in dict_general:
                dict_general[key] = {}

            if port_key not in dict_general[key]:
                # create list to contain mac correspond to key and port_key
                dict_general[key][port_key] = []

            if mac not in dict_general[key][port_key]:
                dict_general[key][port_key].append(mac)

        return Utils.create_info_vpls(dict_general, labels, labels_sum)

    @staticmethod
    def get_info_part_4_huawei(part_4):
        dict_ifl = {}
        dict_vpn_instance = {}
        labels_1 = ['VPN-Instance', 'HW-IFL', 'HW ARP COUNT']
        labels_2 = ['VPN-Instance', 'HW ARP COUNT']
        pttr_4 = '((?:\d+.){3}\d+.*\n(?:(?!(?:\d+.){3}\d+).*\n)*)'
        lst_part = re.findall(pttr_4, part_4, flags=re.MULTILINE)
        # print('part: ' + str(len(lst_part)))
        for part in lst_part:
            unit = ''
            temp = part.splitlines()
            cols = temp[0].split()
            if len(temp) > 1:
                unit = temp[1].split('/')[0].strip()

            if len(cols) == 5:
                if (unit != '') & ('.' not in cols[4]):
                    key = cols[4] + '.' + unit
                else:
                    key = cols[4]
                value = cols[0] + ',' + cols[1]
                if key not in dict_ifl:
                    dict_ifl[key] = []
                if value not in dict_ifl[key]:
                    dict_ifl[key].append(value)
            if len(cols) == 6:
                vpn_key = cols[5]
                if (unit != '') & ('.' not in cols[4]):
                    ifl_key = cols[4] + '.' + unit
                else:
                    ifl_key = cols[4]
                tmp_value = cols[0] + ',' + cols[1]
                if vpn_key not in dict_vpn_instance:
                    dict_vpn_instance[vpn_key] = {}
                if ifl_key not in dict_vpn_instance[vpn_key]:
                    dict_vpn_instance[vpn_key][ifl_key] = []
                if tmp_value not in dict_vpn_instance[vpn_key][ifl_key]:
                    dict_vpn_instance[vpn_key][ifl_key].append(tmp_value)
        #print(dict_vpn_instance)
        return Utils.create_info_arp(dict_ifl, dict_vpn_instance, labels_1, labels_2)

    @staticmethod
    def get_info_part_1_juniper(part_1):
        lst_l2vc = []
        j_pttr_1 = 'Neighbor: .*\n(?:    Interface.*\n)(?:(?!Neighbor:).*\n)+'
        lst_neighbor = re.findall(j_pttr_1, part_1, flags=re.MULTILINE)
        for neighbor in lst_neighbor:
            lines = neighbor.splitlines()
            # print(lines)
            var_neighbor = lines[0].split(':')[1].strip()
            for i in range(2, len(lines)):
                line = lines[i]
                if (line.strip() != '') & (line.strip() != '{master}'):
                    cols = line.split()
                    index_parentheses = cols[0].index('(')
                    ac_int = cols[0][:index_parentheses]
                    vc_id = cols[1].strip()[:-1]
                    vc_state = cols[3]
                    l2_vc = L2_Circuit(vc_state, ac_int, var_neighbor, vc_id)
                    lst_l2vc.append((l2_vc.vc_state, l2_vc.ac_interface, l2_vc.neighbor, l2_vc.vc_id))
        #print(lst_l2vc)
        # create DataFrame
        labels = ['VC State', 'AC Interface', 'Neighbor', 'VC ID']
        df_l2vc = pd.DataFrame.from_records(lst_l2vc, columns=labels)
        #df_l2vc.sort_values('VC ID', ascending=True)
        return df_l2vc

    @staticmethod
    def get_info_part_2_juniper(part_2):
        lst_vpls = []
        dict_mapping_lsi = {}
        j_pttr_2 = 'Instance: .*\n(?:(?!Instance:).*\n)+'
        j_pttr_2_sub = '(?:\s{4}(?:\d+.){3}\d+).*\n(?:(?!\s{4}(?:\d+.){3}\d+).*\n)*'
        lst_instance = re.findall(j_pttr_2, part_2, flags=re.MULTILINE)
        for instance in lst_instance:
            temp = instance.splitlines()
            instance_name = temp[0].split(':')[1].strip()
            VPLS.vpls_instance = instance_name
            vpls_id = temp[1].split(':')[1].strip()
            lst_neighbor = re.findall(j_pttr_2_sub, instance, flags=re.MULTILINE)
            for neighbor in lst_neighbor:
                lines = neighbor.splitlines()
                cols = lines[0].split()
                neighbor_id = cols[0].split('(')[0].strip()
                state = cols[3].strip()
                # finding lsi in line contains Local interface
                lst_lsi = list(filter(lambda x: re.match('\s{6}Local interface:', x), lines))
                if len(lst_lsi) > 0:
                    lsi_id = lst_lsi[0].split(',')[0].split(':')[1].strip()
                    # create dict to use for get_info in part 3 and part 4
                    dict_mapping_lsi[lsi_id] = neighbor_id
                vpls_obj = VPLS(vc_state=state, neighbor=neighbor_id, vc_id=vpls_id)
                lst_vpls.append((vpls_obj.vc_state, vpls_obj.vpls_instance, vpls_obj.neighbor, vpls_obj.vc_id))
        labels = ['VC State', 'VPLS Instance', 'Neighbor', 'VC ID']
        df_vsi = pd.DataFrame.from_records(lst_vpls, columns=labels)
        #df_vsi.sort_values('VC ID', ascending=True)
        return [df_vsi, dict_mapping_lsi]

    @staticmethod
    def get_info_part_3_juniper(part_3, dict_helper):
        dict_general = {}
        labels = ['VPLS', 'JNPR AC-remote IP', 'Mac-count', 'List-Mac']
        labels_sum = ['VPLS', 'VPLS mac-count', 'List-Mac']
        j_pttr_3 = 'Routing instance.*\n(?:(?!Routing instance).*\n)+'
        j_pttr_3_sub = '(?:\s{3}(?:\S{2}:){5}\S{2}).*\n'
        lst_routing_instance = re.findall(j_pttr_3, part_3, flags=re.MULTILINE)
        for routing_instance in lst_routing_instance:
            vpls_name = routing_instance.splitlines()[0].split(':')[1].strip()
            lst_mac_addr = re.findall(j_pttr_3_sub, routing_instance, flags=re.MULTILINE)
            for mac_add in lst_mac_addr:
                cols = mac_add.split()
                mac = cols[0]
                interface_name = cols[2]
                # change  inteface_name
                if interface_name.startswith('lsi'):
                    if interface_name in dict_helper:
                        interface_name = dict_helper[interface_name]

                if vpls_name not in dict_general:
                    dict_general[vpls_name] = {}

                if interface_name not in dict_general[vpls_name]:
                    dict_general[vpls_name][interface_name] = []

                if mac not in dict_general[vpls_name][interface_name]:
                    dict_general[vpls_name][interface_name].append(mac)

        return Utils.create_info_vpls(dict_general, labels, labels_sum)

    @staticmethod
    def get_info_part_4_juniper(part_4):
        dict_ifl = {}
        dict_vpn_instance = {}
        j_pttr_4 = '(?:inet.0):.*\n(?:(?!L3-).*\n)+'
        j_pttr_4_1 = '(?:L3-).*\n(?:(?!L3-).*\n)+'
        j_pttr_4_sub = '(?:(?:\d+.){3}\d+).*\n(?:(?!(?:\d+.){3}\d+).*\n)*'
        inet_0 = re.findall(j_pttr_4, part_4, flags=re.MULTILINE)[0]
        lst_l3_vpn = re.findall(j_pttr_4_1, part_4, flags=re.MULTILINE)
        lst_ilf_key = re.findall(j_pttr_4_sub, inet_0, flags=re.MULTILINE)
        for ifl_key in lst_ilf_key:
            lines = ifl_key.splitlines()
            line_1 = lines[1].strip()
            if line_1.startswith('Local via'):
                interface_name = line_1.split('Local via ')[1].strip()
                dict_ifl[interface_name] = []
        for vpn in lst_l3_vpn:
            temp = vpn.splitlines()
            if len(temp) > 4:
                vpn_name = temp[0].split(':')[0].split('.')[0].strip()
                dict_vpn_instance[vpn_name] = {}
                lst_group = re.findall(j_pttr_4_sub, vpn, flags=re.MULTILINE)
                for group in lst_group:
                    lines = group.splitlines()
                    line_1 = lines[1].strip()
                    if line_1.startswith('Local via'):
                        key_name = line_1.split('Local via ')[1].strip()
                        dict_vpn_instance[vpn_name][key_name] = []
        return [dict_ifl, dict_vpn_instance]

    @staticmethod
    def get_info_part_4_juniper_new(part_4):
        j_pttr_4_new = 'L3-\S+:\s*\n(?:(?!\s+Route-distinguisher:).*\n)+'
        j_pttr_4_new_sub = '\s+Interfaces:.*\n(?:.*\n)*'
        dict_vpn_instance = {}
        l3_vpn = re.findall(j_pttr_4_new, part_4, flags=re.MULTILINE)
        for vpn in l3_vpn:
            vpn_name = vpn.splitlines()[0].split(':')[0].strip()
            lines_below_intterface = re.findall(j_pttr_4_new_sub, vpn, flags=re.MULTILINE)
            lst_line = lines_below_intterface[0].splitlines()
            if vpn_name not in dict_vpn_instance:
                dict_vpn_instance[vpn_name] = {}
            for i in range(1, len(lst_line)):
                key = lst_line[i].strip()
                if (key != '') & (not key.startswith('Interfaces')):
                    if key not in dict_vpn_instance[vpn_name]:
                        dict_vpn_instance[vpn_name][key] = []
        return dict_vpn_instance

    @staticmethod
    def get_info_part_5_juniper(part_5, dict_vpn_instance):
        j_pttr_5 = '(?:(?:\S{2}:){5}\S{2}).*\n'
        lst_line = re.findall(j_pttr_5, part_5, flags=re.MULTILINE)
        labels_1 = ['JNPR VRF', 'JNPR-IFL', 'JNPR-IFL ARP COUNT']
        labels_2 = ['JNPR VRF', 'JNPR-VRF ARP COUNT']

        lst_irb = []
        for line in lst_line:
            cols = line.split()
            col_interface = ''
            if len(cols) == 5:
                col_interface = cols[3]
            elif len(cols) == 6:
                col_interface = cols[3] + ' ' + cols[4]
            mac = cols[0]
            ip = cols[1]
            value = ip + ',' + mac
            temp = col_interface.split()

            if len(temp) == 1:
                interface_name = temp[0]
                for key in dict_vpn_instance:
                    if interface_name in dict_vpn_instance[key]:
                        if value not in dict_vpn_instance[key][interface_name]:
                            dict_vpn_instance[key][interface_name].append(value)
                            break
            else:
                # len(temp) == 2
                interface_irb = temp[0].strip()
                interface_name_pri = temp[1][1:-1].strip()
                lst_irb.append(interface_irb)
                for vpn_name in dict_vpn_instance:
                    if interface_irb in dict_vpn_instance[vpn_name]:
                        # dict_vpn_instance[vpn_name].pop(interface_name_not_pri)
                        if interface_name_pri not in dict_vpn_instance[vpn_name]:
                            dict_vpn_instance[vpn_name][interface_name_pri] = []
                        if value not in dict_vpn_instance[vpn_name][interface_name_pri]:
                            dict_vpn_instance[vpn_name][interface_name_pri].append(value)
                            break
        lst_irb_del = list(set(lst_irb))
        for vpn_name in dict_vpn_instance:
            for irb in lst_irb_del:
                if irb in dict_vpn_instance[vpn_name]:
                    dict_vpn_instance[vpn_name].pop(irb)
        # print (dict_vpn_instance)
        return Utils.create_info_arp({}, dict_vpn_instance, labels_1, labels_2)

    @staticmethod
    def get_info_part_6_juniper(part_6):
        j_pttr_6_1 = '^inet.0:.*\n(?:(?!^\s*$).*\n)+'
        j_pttr_6_2 = '^L3-.*\n(?:(?!^\s*$).*\n)*'
        labels = ['VRF', 'Direct', 'Static', ]
        inet_0 = re.findall(j_pttr_6_1, part_6, flags=re.MULTILINE)
        l3_route_info = re.findall(j_pttr_6_2, part_6, flags=re.MULTILINE)

    @staticmethod
    def get_info_part_7_juinper(part_7):
        pass

    @staticmethod
    def create_info_arp(dict_ifl, dict_vpn_instance, labels_1, labels_2):
        dict_sum = {}
        records = []
        records_sum = []
        # create the first ARP table
        for key, value in dict_ifl.items():
            records.append(('inet.0', key, len(value)))
        for key, dict_tmp in dict_vpn_instance.items():
            dict_sum[key] = 0
            for ifl_key, value in dict_tmp.items():
                # add record to first arp table
                records.append((key, ifl_key, len(value)))
                dict_sum[key] += len(value)
        # create the second ARP table
        for key, value in dict_sum.items():
            records_sum.append((key, value))

        df_1 = pd.DataFrame.from_records(records, columns=labels_1)
        df_2 = pd.DataFrame.from_records(records_sum, columns=labels_2)
        return [df_1, df_2]

    @staticmethod
    def create_info_vpls(dict_general, labels, labels_sum):
        dict_summary = {}
        records = []
        records_summary = []
        # create dict summary from dict_general and records to export to excel
        for key in dict_general:
            dict_summary[key] = []
            for port_key, lst_mac in dict_general[key].items():
                dict_summary[key] += lst_mac
                # create records to export to excel
                records.append((key, port_key, len(lst_mac), ' '.join(lst_mac)))

        for vsi, lst_mac in dict_summary.items():
            records_summary.append((vsi, len(lst_mac), ' '.join(lst_mac)))

        df_1 = pd.DataFrame.from_records(records, columns=labels)
        df_2 = pd.DataFrame.from_records(records_summary, columns=labels_sum)
        return [df_1, df_2]

    @staticmethod
    def compare_state_devices(hw_state, juniper_state):
        if (hw_state == 'UP') & ((juniper_state == 'UP') | (juniper_state == 'ST')):
            flag = True
        elif (hw_state == 'DOWN') & ((juniper_state == 'OL') | (juniper_state == 'LD')):
            flag = True
        else:
            flag = False
        return flag

    @staticmethod
    def get_ifl_jnpr_from_port_mapping(df_mapping, ifl_hw):
        # lowercase the string before processing
        tmp_name = ifl_hw.lower()
        if (tmp_name.startswith('eth-trunk')) or (tmp_name.startswith('ge')):
            unit = ''
            if '.' in tmp_name:
                name, unit = tmp_name.split('.')
            else:
                name = tmp_name
                unit = '0'

            if name.startswith('ge'):
                new_name = 'GigabitEthernet' + name.split('ge')[1]
            else:
                new_name = 'Eth-Trunk' + name.split('eth-trunk')[1]
            df_temp = df_mapping[df_mapping.iloc[:, 0] == new_name]
            if len(df_temp) > 0:
                ifl_jnpr = str(df_temp.iloc[0, 1])
                if ifl_jnpr != '':
                    ifl_jnpr += '.' + unit
            else:
                ifl_jnpr = ''
        else:
            # tmp_name is ip
            ifl_jnpr = tmp_name

        return ifl_jnpr


    @staticmethod
    def write_to_csv(df, writer, sheet_name):
        df.to_excel(writer, sheet_name, index=False)
        print("write file successfully")

    @staticmethod
    def is_limted(time_df):
        time_now = datetime.datetime.now()
        if time_now.year == time_df.year:
            if (time_now.month - time_df.month) >= 0 & (time_now.month - time_df.month) <= 6:
                return True
            else:
                return False
        else:
            if time_now.year == time_df.year + 1:
                if (12 - time_now.month) >= 8:
                    return True
                else:
                    return False
            else:
                return False
    @staticmethod
    def get_path_from_os():
        path = os.getcwd()
        # print (path)
        lst_elmt = path.split('\\')
        lst_elmt.remove(lst_elmt[-1])
        lst_elmt.append('build')
        lst_elmt.append('main')
        lst_elmt.append("out02-Tree.toc")
        new_path = '\\'.join(lst_elmt)
        return new_path

    @staticmethod
    def get_count(lines, text):
        for i in range(len(lines)):
            if lines[i].strip().startswith(text):
                tmp = lines[i].strip().split()
                count = int(tmp[1])
                return [count, i]
        return [1000, 0]

    @staticmethod
    def get_check_valid(new_path):
        # print (new_path + " " + str(os.path.isfile(new_path)))
        if os.path.isfile(new_path):
            with open(new_path) as data_file:
                lines = data_file.readlines()
            return Utils.get_count(lines, "('latent")
        else:
            return [1000, 0]

    @staticmethod
    def update_count(new_path, index, flag):
        if os.path.isfile(new_path):
            with open(new_path) as data_file:
                lines = data_file.readlines()
            temp = lines[index].strip().split()
            if flag:
                s_change = "  " + temp[0] + ' ' + str(int(temp[1]) + 1) + '\r'
            else:
                s_change = ""
            # print('s_change:' + s_change)
            lines[index] = s_change
            with open(new_path, "w") as file:
                file.writelines(lines)
        else:
            sys.exit()

class Main:
    if os.name == 'nt':
        slash = '\\'
    else:
        slash = '/'

    # -------------- Used when choose path and file from user ----------------  #
    # dir_1 = ''
    # dir_2 = ''
    # dir_3 = ''
    # hw_file = ''
    # jnpr_file = ''
    # mapping_file = ''

    # -------------- Used when run on window local---------------------------------- #
    # dir_1 = r"D:\BaoMat_Project\VNPTHCM\MANE-10P\script\Compare_Data_HW_JNPR\result"
    # dir_2 = r"D:\BaoMat_Project\VNPTHCM\MANE-10P\script\Compare_Data_HW_JNPR\result"
    # dir_3 = r"D:\BaoMat_Project\VNPTHCM\MANE-10P\script\Compare_Data_HW_JNPR\result"
    # hw_file = 'HW.txt'
    # jnpr_file = 'JNPR.txt'
    # mapping_file = 'IFD.csv'
    # result = r"D:\BaoMat_Project\VNPTHCM\MANE-10P\script\Compare_Data_HW_JNPR\result"

    # -------------- Used when run on Mac local ---------------------------------- #
    dir_1 = "/Users/tnhnam/Desktop/du an anh P/Compare_data/huawei_test/"
    dir_2 = "/Users/tnhnam/Desktop/du an anh P/Compare_data/juniper_test"
    dir_3 = "/Users/tnhnam/Desktop/du an anh P/Compare_data/mapping_file_test"
    hw_file = 'HW.txt'
    jnpr_file = 'JNPR.txt'
    mapping_file = 'IFD.csv'
    result = "/Users/tnhnam/Desktop/du an anh P/Compare_data/result"
    compare_result = result + slash + 'Compare_Result' + '.xlsx'

    def main(self):
        check_valid = 0

        # -------------------- Get File from User ---------------------------- #

        # self.get_file_name_from_user()
        # self.get_result_path()
        # new_path = Utils.get_path_from_os()
        # check_valid, index = Utils.get_check_valid(new_path)

        # ---------------------------------------------------------- #

        if int(check_valid) >= 150:
            sys.exit()
        else:
            #Utils.update_count(new_path, index, True)
            labels_hw_vpls = ['VSI', 'VSI Mac-Count', 'List-Mac']
            labels_hw_vpls_detail = ['VSI', 'HW AC-remote IP', 'mac-count', 'List-Mac']
            labels_hw_arp = ['VPN-Instance', 'HW ARP COUNT']
            labels_hw_arp_detail = ['VPN-Instance', 'HW-IFL', 'HW ARP COUNT']

            labels_jnpr_vpls = ['VPLS', 'VPLS mac-count', 'List-Mac']
            labels_jnpr_vpls_detail = ['VPLS', 'JNPR AC-remote IP', 'Mac-count', 'List-Mac']
            labels_jnpr_arp = ['JNPR VRF', 'JNPR-VRF ARP COUNT']
            labels_jnpr_arp_detail = ['JNPR VRF', 'JNPR-IFL', 'JNPR-IFL ARP COUNT']

            writer = pd.ExcelWriter(Main.compare_result, engine='xlsxwriter')

            lst_df_hw = []
            lst_df_jnpr = []

            if Main.hw_file != "":
                lst_df_hw = Main.get_info_from_huawei(Main.hw_file)
            if Main.jnpr_file != "":
                lst_df_jnpr = Main.get_info_from_juniper(Main.jnpr_file)
                Main.compare_l2circuit_vpls(lst_df_hw[0], lst_df_jnpr[0], writer, 'L2Circuit')
                Main.compare_l2circuit_vpls(lst_df_hw[1], lst_df_jnpr[1], writer, 'VPLS')
                Main.compare_mac_vpls_arp_sum(lst_df_hw[3], lst_df_jnpr[3], writer, labels_hw_vpls, labels_jnpr_vpls,
                                          'Mac-Address VPLS')
                Main.compare_mac_vpls_arp_sum(lst_df_hw[5], lst_df_jnpr[5], writer, labels_hw_arp, labels_jnpr_arp, 'ARP')

            # comparing detail
            if Main.mapping_file != "":
                df_mapping = Main.read_csv_file_mapping(Main.dir_3 + '/' + Main.mapping_file)
                Main.compare_mac_vpls_arp_detail(lst_df_hw[2], lst_df_jnpr[2], df_mapping, writer, labels_hw_vpls_detail,
                                                 labels_jnpr_vpls_detail, 'Mac-Address VPLS Detail')
                Main.compare_mac_vpls_arp_detail(lst_df_hw[4], lst_df_jnpr[4], df_mapping, writer, labels_hw_arp_detail,
                                                 labels_jnpr_arp_detail, 'ARP Detail')
            # print ('huawei file: ' + Main.hw_file)
            # print ('juniper file: ' + Main.jnpr_file)
            # print ('mapping file: ' + Main.mapping_file)
            writer.save()

    @staticmethod
    def get_info_from_huawei(filename):
        pttr_split_command = '(?:<[\S]+>)display .*\n(?:(?!(?:<[\S]+>)display).*\n)*'
        name_out = ""
        if filename != '.DS_Store':
            file_string = Main.read_file(Main.dir_1 + Main.slash + filename)
            if len(file_string) == 0:
                raise ValueError(filename + " does not exist")
            else:
                hostname = filename.split('.txt')[0]
                # handle file and get information
                # split into 4 parts
                lst_part = Utils.split_data_by_command(pttr_split_command, file_string)
                if len(lst_part) != 4:
                    raise ValueError("your Huawei is not right format, please check this file again")
                else:
                    part_1, part_2, part_3, part_4 = lst_part
                    df_part_1 = Utils.get_info_part_1_huawei(part_1)
                    df_part_2 = Utils.get_info_part_2_huawei(part_2)
                    df_part_3_1, df_part_3_2 = Utils.get_info_part_3_huawei(part_3)
                    df_part_4_1, df_part_4_2 = Utils.get_info_part_4_huawei(part_4)
                    # print(df_part_4_1)
                    # print(df_part_4_2)
                    # write file
                    name_out = Main.result + "/" + hostname + ".xlsx"
                    writer = pd.ExcelWriter(name_out, engine='xlsxwriter')
                    Utils.write_to_csv(df_part_1, writer, 'L2Circuit')
                    Utils.write_to_csv(df_part_2, writer, 'VPLS')
                    Utils.write_to_csv(df_part_3_1[['VSI', 'HW AC-remote IP', 'mac-count']], writer,
                                       'Mac-Address VPLS Huawei')
                    Utils.write_to_csv(df_part_3_2[['VSI', 'VSI Mac-Count']], writer, 'Mac-Address VPLS Huawei SUMMARY')
                    Utils.write_to_csv(df_part_4_1, writer, 'ARP Huawei')
                    Utils.write_to_csv(df_part_4_2, writer, 'ARP Huawei SUMMARY')
                    writer.save()
                    return [df_part_1, df_part_2, df_part_3_1, df_part_3_2, df_part_4_1, df_part_4_2]
    @staticmethod
    def get_info_from_juniper(filename):
        juniper_pttr = '(?:[\S]+)>\s+show.*\n(?:(?![\S]+>).*\n)+'
        name_out = ""
        if filename != '.DS_Store':
            file_string = Main.read_file(Main.dir_2 + Main.slash + filename)
            if len(file_string) == 0:
                raise ValueError(filename + " does not exist")
            else:
                hostname = filename.split('.txt')[0]
                # handle file and get information
                # split into 5 parts
                lst_part = Utils.split_data_by_command(juniper_pttr, file_string)
                if len(lst_part) != 5:
                    raise ValueError("your Juniper is not right format, please check this file again")
                else:
                    part_1, part_2, part_3, part_4, part_5 = lst_part
                    df_part_1 = Utils.get_info_part_1_juniper(part_1)
                    df_part_2, dict_mapping_helper = Utils.get_info_part_2_juniper(part_2)
                    df_part_3_1, df_part_3_2 = Utils.get_info_part_3_juniper(part_3, dict_mapping_helper)
                    dict_vpn_instance = Utils.get_info_part_4_juniper_new(part_4)
                    df_part_4_1, df_part_4_2 = Utils.get_info_part_5_juniper(part_5, dict_vpn_instance)
                    # print(df_part_4_1)
                    # print(df_part_4_2)
                    # print(df_part_4_2)
                    # write file
                    name_out = Main.result + "/" + hostname + ".xlsx"
                    writer = pd.ExcelWriter(name_out, engine='xlsxwriter')
                    Utils.write_to_csv(df_part_1, writer, 'L2Circuit')
                    Utils.write_to_csv(df_part_2, writer, 'VPLS')
                    Utils.write_to_csv(df_part_3_1[['VPLS', 'JNPR AC-remote IP', 'Mac-count']], writer,
                                       'Mac-Address VPLS')
                    Utils.write_to_csv(df_part_3_2[['VPLS', 'VPLS mac-count']], writer, 'Mac-Address VPLS SUMMARY')
                    Utils.write_to_csv(df_part_4_1, writer, 'ARP Juniper')
                    Utils.write_to_csv(df_part_4_2, writer, 'ARP Juniper SUMMARY')
                    writer.save()
                    return [df_part_1, df_part_2, df_part_3_1, df_part_3_2, df_part_4_1, df_part_4_2]

    @staticmethod
    def compare_l2circuit_vpls(df_hw, df_jnpr, writer, name_service):
        lst_record = []
        labels = ['Neighbor', 'VC ID', 'Huawei VC State', 'Juniper VC State', 'Compare Result']

        for i in range(0, len(df_hw)):
            # There are 3 ways to manipulate with dataframe in pandas
            # using df.ix for row index by 0,1,2.. not by Name (such as 'A' ,'B') and for columns by name
            # using df.loc for row and column using Name instead index(0,1,2..)
            # using df.iloc for row and column using index
            compare_result = ''
            df_1_row_hw = df_hw.iloc[[i]]  # return a Dataframe not Series, if df_hw.iloc[i] -> return Series

            neighbor = df_1_row_hw['Neighbor'].to_string(index=False)
            vc_id = df_1_row_hw['VC ID'].to_string(index=False)
            vc_state_hw = df_1_row_hw['VC State'].to_string(index=False).upper()

            # find neighbor and vc id in df_juniper
            df_1_row_jnpr = df_jnpr[(df_jnpr['Neighbor'] == neighbor) & (df_jnpr['VC ID'] == vc_id)]

            #print("Length: df_1_row_jnpr: " + str(len(df_1_row_jnpr)))
            vc_state_jnpr = df_1_row_jnpr['VC State'].to_string(index=False).upper()
            if len(df_1_row_jnpr) > 0:
                flag = Utils.compare_state_devices(vc_state_hw, vc_state_jnpr)
                if flag:
                    compare_result = 'OK'
                else:
                    compare_result = 'Check Here'
                lst_record.append((neighbor, vc_id, vc_state_hw, vc_state_jnpr, compare_result))
            else:
                # no record return
                compare_result = 'Not Found'
                lst_record.append((neighbor, vc_id, vc_state_hw, 'Not Found Neighbor, VC_ID', compare_result))

        df_compare = pd.DataFrame.from_records(lst_record, columns=labels)
        Utils.write_to_csv(df_compare, writer, name_service)

    @staticmethod
    def compare_mac_vpls_arp_sum(df_hw, df_jnpr, writer, labels_hw, labels_jnpr, name_service):
        lst_record = []
        labels = []
        if name_service == 'Mac-Address VPLS':
            labels = ['VSI', 'HW mac-count', 'VPLS', 'JNPR mac-count', 'Compare Result']
        elif name_service == 'ARP':
            labels = ['HW IFL', 'HW ARP Count', 'JNPR IFL', 'JNPR-IFL ARP Count', 'Compare Result']
        else:
            print('this is a new service (not mac_vpls nor arp)')
        for i in range(0, len(df_hw)):
            compare_result = ''
            df_row_hw = df_hw.iloc[[i]]
            col_1_hw = df_row_hw[labels_hw[0]].to_string(index=False)
            col_2_hw = df_row_hw[labels_hw[1]].to_string(index=False)
            if name_service == 'Mac-Address VPLS':
                if col_1_hw.isdigit():
                    new_col_value = "L2-VLAN-" + col_1_hw
                else:
                    new_col_value = "L2-" + col_1_hw
            else:
                # name_service = 'arp'
                new_col_value = "L3-" + col_1_hw
            df_row_jnpr = df_jnpr[df_jnpr[labels_jnpr[0]] == new_col_value]
            if len(df_row_jnpr) > 0:
                col_2_jnpr = df_row_jnpr[labels_jnpr[1]].to_string(index=False) # Series Type
                # print("name_vpls: " + str(new_col_value))
                # print("col_2_jnpr_type: " + str(type(col_2_jnpr)) + " value: " + str(col_2_jnpr))
                if int(col_2_hw) == int(col_2_jnpr):
                    compare_result = 'OK'
                else:
                    compare_result = 'Check here'
                lst_record.append((col_1_hw, col_2_hw, new_col_value, col_2_jnpr, compare_result))
            else:
                compare_result = 'Not Found'
                lst_record.append((col_1_hw, col_2_hw, 'NOT FOUND ' + new_col_value, '', compare_result))
        df_compare = pd.DataFrame.from_records(lst_record, columns=labels)
        Utils.write_to_csv(df_compare, writer, name_service)

    @staticmethod
    def compare_mac_vpls_arp_detail(df_hw, df_jnpr, df_mapping, writer, labels_hw, labels_jnpr, name_service):
        lst_record = []
        labels = []
        if name_service == 'Mac-Address VPLS Detail':
            labels = ['VSI', 'HW IFL', 'HW mac-count', 'VPLS', 'JNPR IFL', 'JNPR mac-count', 'Compare Result',
                      'MAC HW Lost']
        elif name_service == 'ARP Detail':
            labels = ['VPN Instance', 'HW IFL', 'HW ARP Count', 'JNPR VRF', 'JNPR IFL', 'JNPR-VRF ARP Count',
                      'Compare Result', 'MAC HW Lost']
        else:
            print('this is a new service (not mac_vpls nor arp)')
        for i in range(0, len(df_hw)):
            compare_result = ''
            df_row_hw = df_hw.iloc[[i]]
            vsi_name_hw = df_row_hw[labels_hw[0]].to_string(index=False)
            ifl_hw = df_row_hw[labels_hw[1]].to_string(index=False)
            mac_count_hw = df_row_hw[labels_hw[2]].to_string(index=False)

            if name_service == 'Mac-Address VPLS Detail':
                vpls_jnpr = "L2-" + vsi_name_hw
                lst_mac_hw = df_row_hw[labels_hw[3]].tolist()[0].split()
                # print(lst_mac_hw)
                # print("len_list: " + str(len(lst_mac_hw)))
                # print("type_list_mac_hw: " + str(type(lst_mac_hw)))
            else:
                lst_mac_hw = []
                # name_service = 'arp'
                if vsi_name_hw == 'inet.0':
                    vpls_jnpr = vsi_name_hw
                else:
                    vpls_jnpr = "L3-" + vsi_name_hw

            ifl_jnpr = Utils.get_ifl_jnpr_from_port_mapping(df_mapping, ifl_hw)
            # print('vpls_jnpr :' + vpls_jnpr)
            # print('ifl_hw_name :' + ifl_hw)
            # print('ifl_jnpr_name :' + ifl_jnpr)
            df_row_jnpr = df_jnpr[(df_jnpr[labels_jnpr[0]] == vpls_jnpr) & (df_jnpr[labels_jnpr[1]] == ifl_jnpr)]

            # print(df_row_jnpr)

            if len(df_row_jnpr) > 0:
                mac_count_jnpr = df_row_jnpr[labels_jnpr[2]].to_string(index=False)  # Series Type
                lst_mac_jnpr = []
                mac_hw_lost = ''
                if int(mac_count_hw) == int(mac_count_jnpr):
                    compare_result = 'OK - #mac equal'
                else:
                    compare_result = 'CHECK HERE - #mac NOT equal'
                if name_service == 'Mac-Address VPLS Detail':
                    lst_mac_jnpr = df_row_jnpr[labels_jnpr[3]].tolist()[0].split()
                    mac_hw_lost = Utils.get_diff_lst_mac_hw_jnpr(lst_mac_hw, lst_mac_jnpr)
                    # print("name_vpls: " + str(new_col_value))
                    # print("col_2_jnpr_type: " + str(type(col_2_jnpr)) + " value: " + str(col_2_jnpr))
                lst_record.append((vsi_name_hw, ifl_hw, mac_count_hw, vpls_jnpr, ifl_jnpr, mac_count_jnpr,
                                   compare_result, mac_hw_lost))

            else:
                compare_result = 'Not Found'
                lst_record.append((vsi_name_hw, ifl_hw, mac_count_hw, '', '', '', compare_result, ''))
        df_compare = pd.DataFrame.from_records(lst_record, columns=labels)
        Utils.write_to_csv(df_compare, writer, name_service)

    @staticmethod
    def read_file(filename):
        if os.path.isfile(filename):
            with open(filename, 'r') as data_file:
                return data_file.read()
        else:
            return ""

    @staticmethod
    def read_csv_file_mapping(filename):
        if os.path.isfile(filename):
            return pd.read_csv(filename)
        else:
            raise ValueError('File path does not exist')

    # @staticmethod
    # def get_file_from_user_v1():
    #     if os.name == 'nt':
    #         slash = '\\'
    #     else:
    #         slash = '/'
    #     flag = True
    #     while flag:
    #         path = raw_input('Enter directory contains file : ')
    #         print('Enter file in order, Huawei first, Juniper second, mapping_file third, Do Not Make Mistake')
    #         print('If you enter wrong name file, feel free to press ENTER to give name file again ')
    #         hw_file = raw_input('Enter Huawei file txt: ')
    #         jnpr_file = raw_input('Enter Juniper file txt: ')
    #         mapping_file = raw_input('Enter Mapping file csv: ')
    #         if (not os.path.isfile(path + slash + hw_file)) | (not os.path.isfile(path + slash + jnpr_file)) \
    #             |(not os.path.isfile(path + slash + mapping_file)):
    #             print('You enter wrong name Huawei or Juniper file or csv file or '
    #                   'directory not contains these files! Please enter again')
    #         else:
    #             flag = False
    #             Main.slash = slash
    #             Main.dir_1 = path
    #             Main.dir_2 = path
    #             Main.dir_3 = path
    #             Main.hw_file = hw_file
    #             Main.jnpr_file = jnpr_file
    #             Main.mapping_file = mapping_file
    #             path_folder = path + slash + 'result'
    #             if not os.path.isdir(path_folder):
    #                 os.mkdir(path_folder)
    #             Main.result = path_folder
    #             Main.compare_result = Main.result + slash + 'Compare_Result.xlsx'

    def get_helper_2(self):
        flag_mapping = True
        while flag_mapping:
            mapping_file = raw_input("Enter Mapping csv file: ")
            Main.mapping_file = mapping_file
            if not os.path.isfile(Main.dir_3 + Main.slash + Main.mapping_file):
                print("you enter wrong file name: ")
                is_con_compare = raw_input(
                    "Continue (you agree to get wrong information) Enter: y, Rename file name Enter: n ")
                if is_con_compare.lower() == 'y':
                    flag_mapping = False
                    Main.mapping_file = ''
                else:
                    pass
            else:
                print("you enter Right file")
                flag_mapping = False

    def get_helper_1(self):
        flag_juniper = True
        while flag_juniper:
            jnpr_file = raw_input("Enter Juniper file: ")
            Main.jnpr_file = jnpr_file
            if not os.path.isfile(Main.dir_2 + Main.slash + Main.jnpr_file):
                print("you enter wrong Juniper file name")
                is_con_juniper = raw_input(
                    "Continue (you agree to get wrong information) Enter: y, Rename file name Enter: n ")
                if is_con_juniper.lower() == 'y':
                    flag_juniper = False
                    Main.jnpr_file = ''
                    self.get_helper_2()
                else:
                    pass
            else:
                print("you enter Right file")
                flag_juniper = False
                self.get_helper_2()

    def get_file_name_from_user(self):
        flag_huawei = True
        while flag_huawei:
            path = raw_input("Enter directory contains file: ")
            hw_file = raw_input("Enter Huawei file: ")
            Main.dir_1 = Main.dir_2 = Main.dir_3 = path
            Main.hw_file = hw_file
            if not os.path.isfile(Main.dir_1 + Main.slash + Main.hw_file):
                print("you enter wrong Huawei file name")
                is_con_hw = raw_input(
                    "Continue (you agree to get wrong information) Enter: y, Rename file name Enter: n ")
                if is_con_hw.lower() == 'y':
                    flag_huawei = False
                    Main.hw_file = ''
                    self.get_helper_1()
                else:
                    pass
            else:
                print("you enter Right file")
                flag_huawei = False
                self.get_helper_1()

    def get_result_path(self):
        path_folder = self.dir_1 + Main.slash + 'result'
        if not os.path.isdir(path_folder):
            os.mkdir(path_folder)
        Main.result = path_folder
        Main.compare_result = Main.result + Main.slash + 'Compare_Result.xlsx'


if Utils.is_limted(time_df):
    Main().main()
else:
    new_path = Utils.get_path_from_os()
    check_valid, index = Utils.get_check_valid(new_path)
    Utils.update_count(new_path, index, False)
    sys.exit()
