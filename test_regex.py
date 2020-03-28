import re

if __name__ == '__main__':
    pttr = '\s{4,6}'
    txt = 'MAC Address: 70e4-224b-a659      VLAN/BD/VSI/SI/EVPN: mobi-quanly-HTB_NodeB '
    check = re.split(pttr, txt)
    print(check)
    # if check:
    #     print(f'found: {check.group()}')
    # else:
    #     print(f'not found')
