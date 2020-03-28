import os
import datetime
import pandas as pd
import sys
from service_obj import *
from utils import Utils
from pathlib import Path


time_df = datetime.datetime(2020, 3, 1, 18, 15, 0, 0)


class Main:
    # if os.name == 'nt':
    #     slash = '\\'
    # else:
    #     slash = '/'

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

    dir_1 = os.getcwd() + "/BTN_services"
    dir_2 = os.getcwd() + '/juniper_services'
    dir_3 = os.getcwd() + '/mapping'
    hw_file = 'GLI03AYA_H_baseline_script.txt'
    jnpr_file = 'GLI03AYA_J_baseline_script.txt'
    mapping_file = 'MX-DTH.txt'
    btn_result = os.getcwd() + "/btn_result"
    jnpr_result = os.getcwd() + "/juniper_result"
    result = os.getcwd() + "/compare_result"
    compare_result = Path.joinpath(Path(result), 'compare_result.xlsx')

    def main(self):
        check_valid = 0
        new_path = ''
        # -------------------- Get File from User ---------------------------- #

        # self.get_file_name_from_user()
        # self.get_result_path()
        # new_path = Utils.get_path_from_os()
        # check_valid, index = Utils.get_check_valid(new_path)

        # ---------------------------------------------------------- #

        if int(check_valid) >= 150:
            sys.exit()
        else:
            if new_path != '':
                Utils.update_count(new_path, index, True)
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
                Main.compare_mac_vpls_arp_sum(lst_df_hw[3], lst_df_jnpr[3], lst_df_hw[1], writer, labels_hw_vpls,
                                              labels_jnpr_vpls,
                                          'Mac-Address VPLS')
                Main.compare_mac_vpls_arp_sum(lst_df_hw[5], lst_df_jnpr[5], lst_df_hw[1], writer, labels_hw_arp,
                                              labels_jnpr_arp, 'ARP')
            if (len(lst_df_hw) > 6) & (len(lst_df_jnpr) > 6):
                # adding new compare route for new command
                df_vrf_sum, df_route_detail = Main.compare_route(lst_df_hw[6], lst_df_hw[7], lst_df_jnpr[6],
                                                                 lst_df_jnpr[7], lst_df_hw[8])
                Utils.write_to_csv(df_vrf_sum, writer, 'Route_Summary_Compare')
                Utils.write_to_csv(df_route_detail, writer, 'Lost_Route_Info')
            # comparing detail
            if Main.mapping_file != "":
                df_mapping = Main.read_csv_file_mapping(Path.joinpath(Path(Main.dir_3), Main.mapping_file))
                Main.compare_mac_vpls_arp_detail(lst_df_hw[2], lst_df_jnpr[2], df_mapping, lst_df_hw[1], writer,
                                                 labels_hw_vpls_detail,
                                                 labels_jnpr_vpls_detail, 'Mac-Address VPLS Detail')
                Main.compare_mac_vpls_arp_detail(lst_df_hw[4], lst_df_jnpr[4], df_mapping, lst_df_hw[1], writer,
                                                 labels_hw_arp_detail,
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
            file_string = Main.read_file(Path.joinpath(Path(Main.dir_1), filename))
            if len(file_string) == 0:
                raise ValueError(filename + " does not exist")
            else:
                hostname = filename.split('.txt')[0]
                # handle file and get information
                # split into 4 parts
                lst_part = Utils.split_data_by_command(pttr_split_command, file_string)
                if len(lst_part) < 4:
                    raise ValueError("your Huawei is not right format, please check this file again")
                else:
                    part_1, part_2, part_3, part_4 = lst_part[0:4]
                    df_part_1 = Utils.get_info_part_1_huawei(part_1)
                    df_part_2 = Utils.get_info_part_2_huawei(part_2)
                    df_part_3_1, df_part_3_2 = Utils.get_info_part_3_huawei(part_3)
                    df_part_4_1, df_part_4_2 = Utils.get_info_part_4_huawei(part_4)
                    # print(df_part_4_1)
                    # print(df_part_4_2)
                    # write file
                    name_out = Main.btn_result + "/" + hostname + ".xlsx"
                    writer = pd.ExcelWriter(name_out, engine='xlsxwriter')
                    Utils.write_to_csv(df_part_1, writer, 'L2Circuit')
                    Utils.write_to_csv(df_part_2, writer, 'VPLS')
                    Utils.write_to_csv(df_part_3_1[['VSI', 'HW AC-remote IP', 'mac-count']], writer,
                                       'Mac-Address VPLS Huawei')
                    Utils.write_to_csv(df_part_3_2[['VSI', 'VSI Mac-Count']], writer, 'Mac-Address VPLS Huawei SUMMARY')
                    Utils.write_to_csv(df_part_4_1, writer, 'ARP Huawei')
                    Utils.write_to_csv(df_part_4_2, writer, 'ARP Huawei SUMMARY')
                    if len(lst_part) > 4:
                        # adding more display command in HW
                        df_route_sum, df_route_detail, lst_vrf_name = Utils.get_info_the_rest_huawei(lst_part[4:])
                        Utils.write_to_csv(df_route_sum, writer, 'Route SUMMARY')
                        Utils.write_to_csv(df_route_detail, writer, 'Route Detail SUMMARY')
                        writer.save()
                        return [df_part_1, df_part_2, df_part_3_1, df_part_3_2, df_part_4_1, df_part_4_2, df_route_sum,
                            df_route_detail, lst_vrf_name]
                    else:
                        writer.save()
                        return [df_part_1, df_part_2, df_part_3_1, df_part_3_2, df_part_4_1, df_part_4_2]

    @staticmethod
    def get_info_from_juniper(filename):
        juniper_pttr = '(?:[\S]+)>\s+show.*\n(?:(?![\S]+>).*\n)+'
        name_out = ""
        if filename != '.DS_Store':
            file_string = Main.read_file(Path.joinpath(Path(Main.dir_2), filename))
            if len(file_string) == 0:
                raise ValueError(filename + " does not exist")
            else:
                hostname = filename.split('.txt')[0]
                # handle file and get information
                # split into 5 parts
                lst_part = Utils.split_data_by_command(juniper_pttr, file_string)
                if len(lst_part) < 5:
                    raise ValueError("your Juniper is not right format, please check this file again")
                else:
                    part_1, part_2, part_3, part_4, part_5 = lst_part[0:5]
                    df_part_1 = Utils.get_info_part_1_juniper(part_1)
                    df_part_2, dict_mapping_helper = Utils.get_info_part_2_juniper(part_2)
                    df_part_3_1, df_part_3_2 = Utils.get_info_part_3_juniper(part_3, dict_mapping_helper)
                    dict_vpn_instance = Utils.get_info_part_4_juniper_new(part_4)
                    df_part_4_1, df_part_4_2 = Utils.get_info_part_5_juniper(part_5, dict_vpn_instance)

                    # write file
                    name_out = Main.jnpr_result + "/" + hostname + ".xlsx"
                    writer = pd.ExcelWriter(name_out, engine='xlsxwriter')
                    Utils.write_to_csv(df_part_1, writer, 'L2Circuit')
                    Utils.write_to_csv(df_part_2, writer, 'VPLS')
                    Utils.write_to_csv(df_part_3_1[['VPLS', 'JNPR AC-remote IP', 'Mac-count']], writer,
                                       'Mac-Address VPLS')
                    Utils.write_to_csv(df_part_3_2[['VPLS', 'VPLS mac-count']], writer, 'Mac-Address VPLS SUMMARY')
                    Utils.write_to_csv(df_part_4_1, writer, 'ARP Juniper')
                    Utils.write_to_csv(df_part_4_2, writer, 'ARP Juniper SUMMARY')
                    if len(lst_part) > 5:
                        # adding more show command in JNPR
                        part_6, part_7 = lst_part[5:]
                        df_part_6 = Utils.get_info_part_6_juniper(part_6)
                        df_part_7 = Utils.get_info_part_7_juniper(part_7)
                        Utils.write_to_csv(df_part_6, writer, 'Route SUMMARY')
                        Utils.write_to_csv(df_part_7, writer, 'Route Detail SUMMARY')
                        writer.save()
                        return [df_part_1, df_part_2, df_part_3_1, df_part_3_2, df_part_4_1, df_part_4_2, df_part_6,
                                df_part_7]
                    else:
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
    def compare_mac_vpls_arp_sum(df_hw, df_jnpr, df_hw_ref, writer, labels_hw, labels_jnpr, name_service):
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
            list_vsi_name_ref = df_hw_ref["VPLS Instance"].tolist()
            if name_service == 'Mac-Address VPLS':
                name = col_1_hw.strip()
                if (name.isdigit()) & (name not in list_vsi_name_ref):
                    new_col_value = "L2-VLAN-" + name
                else:
                    new_col_value = "L2-" + name
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
    def compare_mac_vpls_arp_detail(df_hw, df_jnpr, df_mapping, df_hw_ref, writer, labels_hw, labels_jnpr,
                                    name_service):
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
            list_vsi_name_ref = df_hw_ref["VPLS Instance"].tolist()
            if name_service == 'Mac-Address VPLS Detail':
                if (vsi_name_hw.strip().isdigit()) & (vsi_name_hw.strip() not in list_vsi_name_ref):
                    vpls_jnpr = "L2-VLAN-" + vsi_name_hw
                    ifl_hw = ifl_hw + '.' + vsi_name_hw
                else:
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
    def compare_route(df_hw_sum, df_hw_detail, df_jnpr_sum, df_jnpr_detail, lst_hw_vrf_name):
        labels_sum = ['HW_VRF', 'HW_BGP', 'HW_ISIS', 'HW_OSPF', 'HW_DIRECT', 'HW_STATIC', 'HW_RIP',
                      'JNPR_VRF', 'JNPR_BGP', 'JNPR_ISIS', 'JNPR_OSPF', 'HW_DIRECT', 'HW_STATIC', 'HW_RIP',
                      'RESULT']
        labels_route_detail = ['VRF', 'Protocol', 'List of LOST Routes']
        lst_protocol = ['BGP', 'IS-IS', 'OSPF', 'DIRECT', 'STATIC', 'RIP']
        lst_records_vrf = []
        lst_records_route = []
        flag_check = False
        for hw_vrf_name in lst_hw_vrf_name:
            check_protocol = {'DIRECT': True, 'STATIC': True, 'RIP': True, 'OSPF': True, 'IS-IS': True, 'BGP': True}
            result = 'OK'
            df_hw_vrf = df_hw_sum[df_hw_sum['VRF'] == hw_vrf_name]
            if hw_vrf_name == 'INET.0':
                jnpr_vrf_name = 'INET.0'
            else:
                jnpr_vrf_name = 'L3-' + hw_vrf_name
            # print("hw_vrf_name: " + hw_vrf_name)
            df_jnpr_vrf = df_jnpr_sum[df_jnpr_sum['VRF'] == jnpr_vrf_name]
            hw_route = Route()
            jnpr_route = Route()
            if len(df_jnpr_vrf) > 0:
                Main.get_check_protocol_helper(df_hw_vrf, df_jnpr_vrf, check_protocol)
                # check any protocol is mismatch
                for key, value in check_protocol.items():
                    if not value:
                        flag_check = True
                        result = 'Check Here'
                        break
                # create lst_records_route for LOST route
                if flag_check:
                    lst_records_route += Main.get_lost_route_detail(df_hw_detail, df_jnpr_detail, check_protocol,
                                                                    hw_vrf_name, jnpr_vrf_name)
                # create lst_record_vrf
                for protocol in lst_protocol:
                    hw_route.get_info(df_hw_vrf, protocol)
                    jnpr_route.get_info(df_jnpr_vrf, protocol)
            else:
                result = 'Critical'
                jnpr_vrf_name += ' NOT FOUND'
                for protocol in lst_protocol:
                    hw_route.get_info(df_hw_vrf, protocol)
            lst_records_vrf.append((hw_vrf_name, hw_route.bgp, hw_route.isis, hw_route.ospf, hw_route.direct,
                                    hw_route.static, hw_route.rip,
                                    jnpr_vrf_name, jnpr_route.bgp, jnpr_route.isis, jnpr_route.ospf, jnpr_route.direct,
                                    jnpr_route.static, jnpr_route.rip,
                                    result))
        # this case is perfect when HW and JNPR perfect MATCH
        if len(lst_records_route) == 0:
            lst_records_route.append(('NULL', 'NULL', 'NULL'))
        df_vrf_sum = pd.DataFrame.from_records(lst_records_vrf, columns=labels_sum)
        df_route_detail = pd.DataFrame.from_records(lst_records_route, columns=labels_route_detail)
        return [df_vrf_sum, df_route_detail]

    @staticmethod
    def get_lost_route_detail(df_hw_detail, df_jnpr_detail, check_protocol, hw_vrf_name, jnpr_vrf_name):
        lst_records = []
        for key, value in check_protocol.items():
            if not value:
                df_hw_route_vrf_pro = df_hw_detail[
                    (df_hw_detail['VRF'] == hw_vrf_name) & (df_hw_detail['Protocol'] == key)]
                df_jnpr_route_vrf_pro = df_jnpr_detail[
                    (df_jnpr_detail['VRF'] == jnpr_vrf_name) & (df_jnpr_detail['Protocol'] == key)]
                set_hw_route = set(df_hw_route_vrf_pro['Route'].tolist())
                set_jnpr_route = set(df_jnpr_route_vrf_pro['Route'].tolist())
                list_diff_route = list(set_hw_route.difference(set_jnpr_route))
                for route in list_diff_route:
                    lst_records.append((hw_vrf_name, key, route))
        return lst_records

    @staticmethod
    def get_check_protocol_helper(df_hw_vrf, df_jnpr_vrf, check_protocol):
        for key in check_protocol:
            hw_num_of_key = int(df_hw_vrf[key].to_string(index=False))
            jnpr_num_of_key = int(df_jnpr_vrf[key].to_string(index=False))
            if hw_num_of_key != jnpr_num_of_key:
                check_protocol[key] = False

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
    #         path = input('Enter directory contains file : ')
    #         print('Enter file in order, Huawei first, Juniper second, mapping_file third, Do Not Make Mistake')
    #         print('If you enter wrong name file, feel free to press ENTER to give name file again ')
    #         hw_file = input('Enter Huawei file txt: ')
    #         jnpr_file = input('Enter Juniper file txt: ')
    #         mapping_file = input('Enter Mapping file csv: ')
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
            mapping_file = input("Enter Mapping csv file: ")
            Main.mapping_file = mapping_file
            if not os.path.isfile(Path.joinpath(Path(Main.dir_3), Main.mapping_file)):
                print("you enter wrong file name: ")
                is_con_compare = input(
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
            jnpr_file = input("Enter Juniper file: ")
            Main.jnpr_file = jnpr_file
            if not os.path.isfile(Path.joinpath(Path(Main.dir_2), Main.jnpr_file)):
                print("you enter wrong Juniper file name")
                is_con_juniper = input(
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
            path = input("Enter directory contains file: ")
            hw_file = input("Enter Huawei file: ")
            Main.dir_1 = Main.dir_2 = Main.dir_3 = path
            Main.hw_file = hw_file
            if not os.path.isfile(Path.joinpath(Path(Main.dir_1), Main.hw_file)):
                print("you enter wrong Huawei file name")
                is_con_hw = input(
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
        path_folder = Path.joinpath(Path(self.dir_1), 'result')
        if not os.path.isdir(path_folder):
            os.mkdir(path_folder)
        Main.result = path_folder
        Main.compare_result = Path.joinpath(Path(Main.result), 'Compare_Result.xlsx')


if Utils.is_limted(time_df):
    if __name__ == '__main__':
        Main().main()
else:
    new_path = Utils.get_path_from_os()
    check_valid, index = Utils.get_check_valid(new_path)
    Utils.update_count(new_path, index, False)
    sys.exit()
