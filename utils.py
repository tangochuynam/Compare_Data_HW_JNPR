import sys

from service_obj import *
import re
import pandas as pd
import datetime
import os


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
                    tmp[0] = tmp[0].strip().lower()
                    tmp[1] = tmp[1].strip().lower()
                    if tmp[0] == 'client interface':
                        l2_vc.ac_interface = tmp[1]
                    if tmp[0] == 'vc state':
                        l2_vc.vc_state = tmp[1]
                    if tmp[0] == 'vc id':
                        l2_vc.vc_id = tmp[1]
                    if tmp[0] == 'destination':
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
        pttr_2_sub = '^\d+.*\n'
        lst_vsi = re.findall(pttr_2, part_2, flags=re.MULTILINE)
        for vsi in lst_vsi:
            lines = vsi.split('\n')
            VPLS.vpls_instance = lines[0].split()[2].strip()
            lst_peer = re.findall(pttr_2_sub, vsi, flags=re.MULTILINE)
            for peer in lst_peer:
                vpls = VPLS()
                cols = peer.split()
                vpls.neighbor, vpls.vc_id, vpls.vc_state = cols[0], cols[1], cols[4]
                lst_vsi_store.append((vpls.vc_state, vpls.vpls_instance, vpls.neighbor, vpls.vc_id))
        labels = ['VC State', 'VPLS Instance', 'Neighbor', 'VC ID']
        df_vsi = pd.DataFrame.from_records(lst_vsi_store, columns=labels)
        #df_vsi.sort_values(['Neighbor', 'VC ID'], ascending=[True, True])
        return df_vsi


    @staticmethod
    def get_info_part_3_huawei(part_3):
        dict_general = {}
        pttr_3 = 'MAC Address:.*\n(?:(?!MAC Address:).*\n)+'
        pttr_mac = 'MAC [aA]ddress: .*VLAN.*'
        pttr_port = 'Port.*Type.*'
        pttr_peerip = 'Peer IP.*VC-ID.*'
        labels = ['VSI', 'HW AC-remote IP', 'mac-count', 'List-Mac']
        labels_sum = ['VSI', 'VSI Mac-Count', 'List-Mac']
        lst_mac_add = re.findall(pttr_3, part_3, flags=re.MULTILINE)
        for mac_dd in lst_mac_add:
            # lines = mac_dd.split('\n')
            # just consider line[0] - mac address, line[1] - port, line[3]- peer ip
            check_mac = re.search(pttr_mac, mac_dd)
            check_peerip = re.search(pttr_peerip, mac_dd)
            if check_mac and check_peerip:
                line_mac = check_mac.group()
                line_peer = check_peerip.group()
            else:
                print(f'mac_dd : {mac_dd}')
                raise ValueError('can not found the line Mac Address .... VLAN.... or '
                                 'Peer IP.... VC-ID '
                                 'in the display mac-address')

            line_peerip_part = re.split('VC-ID', line_peer)
            # check peerip_part first if peer-ip == '-' check port type and get port
            peer_ip = line_peerip_part[0].split(':')[1].strip()
            if peer_ip != '-':
                port_key = peer_ip
            else:
                check_port = re.search(pttr_port, mac_dd)
                if check_port:
                    line_port = check_port.group()
                    line_port_part = re.split('[tT]ype', line_port)
                    port_key = line_port_part[0].split(':')[1].strip()
                else:
                    raise ValueError('can not found the line Port:......Type: in display mac-address')

            line_mac_part = re.split('\s{4,6}', line_mac)
            mac_tmp = line_mac_part[0].split(':')[1].strip()
            mac = Utils.convert_mac_to_jnpr_form(mac_tmp)
            key = line_mac_part[1].split(':')[1].strip()

            # if port_key.startswith('Tun'):
            #     index_vc_id = line_peer.find('VC-ID')
            #     peer_ip = line_peer[:index_vc_id].split(':')[1].strip()
            #     port_key = peer_ip

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
    def get_info_the_rest_huawei(lst_part):
        h_pttr_other = '(?:^\s|^\d{1,3})\s*\d+.*\n(?:(?!\s*\d{1,3}).*\n)*'
        h_pttr_vrf_name = 'Routing Tables.*\n'
        labels_sum = ['VRF', 'DIRECT', 'STATIC', 'RIP', 'OSPF', 'IS-IS', 'BGP']
        labesl_detail = ['VRF', 'Route', 'Protocol', 'Next-Hop and Interface']
        lst_route_sum = []
        lst_route_detail = []
        lst_vrf_name = []
        for part in lst_part:
            line_vrf_name = re.findall(h_pttr_vrf_name, part, flags=re.MULTILINE)
            lines_route = re.findall(h_pttr_other, part, flags=re.MULTILINE)
            vrf_name = line_vrf_name[0].splitlines()[0].split(':')[1].strip().upper()
            if vrf_name == 'PUBLIC':
                vrf_name = 'inet.0'.upper()
            # store list vrf_name for compare later
            lst_vrf_name.append(vrf_name)
            route_info = Route()
            # print ('vrf_name: ' + vrf_name)
            for i in range(0, len(lines_route)):
                lines = lines_route[i]
                route = ''
                protocol = ''
                next_hop_interface = ''
                if i == 0:
                    info = lines.splitlines()[1].strip().split()
                    route, protocol, next_hop_interface = Utils.get_route_info_HW(info, route_info, True)
                else:
                    lst_tmp = lines.splitlines()
                    if len(lst_tmp) == 1:
                        info = lst_tmp[0].split()
                        route, protocol, next_hop_interface = Utils.get_route_info_HW(info, route_info, True)
                    else:
                        # truong hop 1 route co nhieu hon 1 next hop (next-hop >=2)
                        destination = ''
                        flag = True
                        for j in range(0, len(lst_tmp)):
                            if j == 0:
                                info = lst_tmp[j].split()
                                route, protocol, next_hop_interface = Utils.get_route_info_HW(info, route_info, flag)
                                destination = info[0]
                                flag = False
                            else:
                                tmp = lst_tmp[j].split()
                                if len(tmp) > 0:
                                    # print("value of TMP")
                                    # print(tmp)
                                    tmp.insert(0, destination)
                                    lst_info_tmp = Utils.get_route_info_HW(tmp, route_info, flag)
                                    next_hop_interface += ', ' + lst_info_tmp[2]
                lst_route_detail.append((vrf_name, route, protocol, next_hop_interface))
            lst_route_sum.append((vrf_name, route_info.direct, route_info.static, route_info.rip, route_info.ospf,
                                  route_info.isis, route_info.bgp))
        # create dataframe for compare and export to excel
        df_route_sum = pd.DataFrame.from_records(lst_route_sum, columns=labels_sum)
        df_route_detail = pd.DataFrame.from_records(lst_route_detail, columns=labesl_detail)
        return [df_route_sum, df_route_detail, lst_vrf_name]

    @staticmethod
    def get_route_info_HW(info, route_info, flag):
        route = info[0]
        next_hop = info[5]
        interface = info[6]
        next_hop_interface = '(' + next_hop + ', ' + interface + ')'
        protocol = Utils.convert_protocol_and_count_HW(info[1], route_info, flag)
        return [route, protocol, next_hop_interface]

    @staticmethod
    def convert_protocol_and_count_HW(p, route_info, flag):
        protocol = ''
        p = p.upper()
        if p == 'ISIS-L1':
            protocol = 'IS-IS'
            if flag:
                route_info.isis += 1
        elif p == 'IBGP':
            protocol = 'BGP'
            if flag:
                route_info.bgp += 1
        elif p == 'DIRECT':
            protocol = 'DIRECT'
            if flag:
                route_info.direct += 1
        elif p == 'RIP':
            protocol = 'RIP'
            if flag:
                route_info.rip += 1
        elif p == 'STATIC':
            protocol = 'STATIC'
            if flag:
                route_info.static += 1
        elif p == 'OSPF':
            protocol = 'OSPF'
            if flag:
                route_info.ospf += 1
        return protocol

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
            if len(lines_below_intterface) > 0:
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
        lst_route = []
        labels = ['VRF', 'DIRECT', 'STATIC', 'RIP', 'OSPF', 'IS-IS', 'BGP']
        inet_0 = re.findall(j_pttr_6_1, part_6, flags=re.MULTILINE)
        lst_l3 = re.findall(j_pttr_6_2, part_6, flags=re.MULTILINE)
        lst_line_inet_0 = inet_0[0].splitlines()

        # handle the inet.0
        name_vrf_inet = lst_line_inet_0[0].split(':')[0].strip().upper()
        route = Route()
        for i in range(1, len(lst_line_inet_0)):
            Utils.get_num_active_route(lst_line_inet_0[i], route)
        lst_route.append((name_vrf_inet, route.direct, route.static, route.rip, route.ospf, route.isis, route.bgp))

        # handle the L3-
        for l3 in lst_l3:
            lst_line_l3 = l3.splitlines()
            name_vrf_l3 = lst_line_l3[0].split(':')[0].strip().upper().split('.INET.0')[0]
            route = Route()
            for i in range(1, len(lst_line_l3)):
                Utils.get_num_active_route(lst_line_l3[i], route)
            lst_route.append((name_vrf_l3, route.direct, route.static, route.rip, route.ospf, route.isis, route.bgp))

        df_route_sum = pd.DataFrame.from_records(lst_route, columns=labels)
        return df_route_sum

    @staticmethod
    def get_info_part_7_juniper(part_7):
        j_pttr_7_1 = '^inet.0:.*\n(?:(?!^inet.1).*\n)+'
        j_pttr_7_2 = '^L3-.*\n(?:(?!(?:^L3-|^iso.0)).*\n)*'
        j_pttr_7_3 = '^\d+.*\n'
        j_pttr_7_4 = '^inet.0.*\n'
        j_pttr_7_5 = '^L3-.*\n'
        lst_route = []
        lst_protocol = ['DIRECT', 'RIP', 'BGP', 'OSPF', 'STATIC', 'IS-IS']
        labels = ['VRF', 'Route', 'Protocol']
        inet_0 = re.findall(j_pttr_7_1, part_7, flags=re.MULTILINE)
        lst_l3 = re.findall(j_pttr_7_2, part_7, flags=re.MULTILINE)

        # handle the inet_0
        vrf_name_inet = Utils.get_name_vrf_for_part_7_juniper(inet_0[0], j_pttr_7_4)
        lst_line_inet = re.findall(j_pttr_7_3, inet_0[0], flags=re.MULTILINE)
        for line_inet in lst_line_inet:
            route, protocol = Utils.get_route_protcol_part7_juniper(line_inet)
            if protocol in lst_protocol:
                lst_route.append((vrf_name_inet, route, protocol))
        # handle the l3
        for l3 in lst_l3:
            vrf_name_l3 = Utils.get_name_vrf_for_part_7_juniper(l3, j_pttr_7_5)
            lst_line_l3 = re.findall(j_pttr_7_3, l3, flags=re.MULTILINE)
            for line_l3 in lst_line_l3:
                route, protocol = Utils.get_route_protcol_part7_juniper(line_l3)
                if protocol in lst_protocol:
                    lst_route.append((vrf_name_l3, route, protocol))
        df_route_detail = pd.DataFrame.from_records(lst_route, columns=labels)
        return df_route_detail

    @staticmethod
    def get_name_vrf_for_part_7_juniper(part, pttr):
        first_line = re.findall(pttr, part, flags=re.MULTILINE)
        return first_line[0].split(':')[0].strip().upper().split('.INET.0')[0]

    @staticmethod
    def get_route_protcol_part7_juniper(line):
        tmp = line.split()
        route = tmp[0].strip()
        protocol = ''
        if '/' in tmp[1]:
            index_first_square_bracket = tmp[1].index('[')
            index_slash = tmp[1].index('/')
            protocol = tmp[1][index_first_square_bracket + 1:index_slash].upper()
            if protocol == 'ACCESS-INTERNAL':
                protocol = 'DIRECT'
        else:
            raise ValueError('protocol name in VRF does not have / like [BGP/170]')
        return [route, protocol]

    @staticmethod
    def get_num_active_route(line, route):
        tmp_line = line.strip()
        tmp_1 = tmp_line.split(':')
        route_name = tmp_1[0].lower()
        num_active = tmp_1[1].split(',')[1].strip().split()[0]
        if route_name == 'direct':
            route.direct = num_active
        elif route_name == 'static':
            route.static = num_active
        elif route_name == 'rip':
            route.rip = num_active
        elif route_name == 'ospf':
            route.ospf = num_active
        elif route_name == 'is-is':
            route.isis = num_active
        elif route_name == 'bgp':
            route.bgp = num_active
        else:
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