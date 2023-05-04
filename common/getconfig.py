#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import platform
import yaml
from loguru import logger

ostype = platform.system().lower()
pwd_and_file = os.path.abspath(__file__)
pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain
root_path = os.path.realpath(f'{pwd}/../')
# grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
# print(grader_father) # E:\ccode\python\006_lunzi\core



def getconfig():
    toolsyaml_path = f"{root_path}/config/config.yaml"
    # toolsyaml_path = "tools_linux.yaml"
    if os.path.exists(toolsyaml_path):
        with open(toolsyaml_path, 'r', encoding='utf-8') as f:
            all_config = yaml.load(f, Loader=yaml.FullLoader)
            return all_config
            # tools_config =all_config['tools']
            # print(tools_config)
    else:
        logger.error(f"[-] not found {toolsyaml_path}")
        logger.error("Exit!")
        exit(1)


if __name__ == '__main__':
    getconfig()


