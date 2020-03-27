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


class Route:
    def __init__(self):
        self.direct = 0
        self.static = 0
        self.rip = 0
        self.ospf = 0
        self.isis = 0
        self.bgp = 0

    def get_info(self, df_vrf, protocol):

        if protocol == 'BGP':
            self.bgp = int(df_vrf['BGP'].to_string(index=False))
        elif protocol == 'OSPF':
            self.ospf = int(df_vrf['OSPF'].to_string(index=False))
        elif protocol == 'IS-IS':
            self.isis = int(df_vrf['IS-IS'].to_string(index=False))
        elif protocol == 'DIRECT':
            self.direct = int(df_vrf['DIRECT'].to_string(index=False))
        elif protocol == 'STATIC':
            self.static = int(df_vrf['STATIC'].to_string(index=False))
        elif protocol == 'RIP':
            self.rip = int(df_vrf['RIP'].to_string(index=False))
        else:
            raise ValueError('No protocol found')


class Route_Detail:
    def __init__(self, vrf_name='', route='', protocol=''):
        self.vrf_name = vrf_name
        self.route = route
        self.protocol = protocol

