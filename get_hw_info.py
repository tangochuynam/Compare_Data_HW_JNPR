from Main import Main
import os
from pathlib import Path
if __name__ == '__main__':

    # lst_file = os.listdir(Path.joinpath(Path(os.getcwd()), 'BTN_services'))
    lst_file = ['BTN01PT1-services.log']
    for hw_file in lst_file:
        print(f'file name: {hw_file}')
        _ = Main.get_info_from_huawei(hw_file)