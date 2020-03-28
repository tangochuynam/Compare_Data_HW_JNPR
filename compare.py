from Main import Main
import pandas as pd
from utils import Utils
from pathlib import Path

if __name__ == '__main__':
    hw = 'BTN01PT1-services.log'
    jnpr = 'MX-DTH.txt'
    labels_hw_vpls = ['VSI', 'VSI Mac-Count', 'List-Mac']
    labels_hw_vpls_detail = ['VSI', 'HW AC-remote IP', 'mac-count', 'List-Mac']
    labels_hw_arp = ['VPN-Instance', 'HW ARP COUNT']
    labels_hw_arp_detail = ['VPN-Instance', 'HW-IFL', 'HW ARP COUNT']

    labels_jnpr_vpls = ['VPLS', 'VPLS mac-count', 'List-Mac']
    labels_jnpr_vpls_detail = ['VPLS', 'JNPR AC-remote IP', 'Mac-count', 'List-Mac']
    labels_jnpr_arp = ['JNPR VRF', 'JNPR-VRF ARP COUNT']
    labels_jnpr_arp_detail = ['JNPR VRF', 'JNPR-IFL', 'JNPR-IFL ARP COUNT']

    writer = pd.ExcelWriter(Main.compare_result, engine='xlsxwriter')

    # begin getting info and compare
    lst_df_hw = Main.get_info_from_huawei(hw)
    lst_df_jnpr = Main.get_info_from_juniper(jnpr)
    print('--------------------------------------------------------------')
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

    writer.save()