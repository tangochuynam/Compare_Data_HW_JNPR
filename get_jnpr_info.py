from Main import Main
import os
from pathlib import Path
if __name__ == '__main__':

    lst_file = os.listdir(Path.joinpath(Path(os.getcwd()), 'juniper_services'))
    # lst_file = ['BTN01PT1-services.log']
    for jnpr_file in lst_file:
        print(f'file name: {jnpr_file}')
        _ = Main.get_info_from_juniper(jnpr_file)