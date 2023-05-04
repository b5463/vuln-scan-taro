import os
import sys
from pprint import pprint
import shutil
import tarfile
import threading
import time
import traceback
import zipfile
import py7zr
from pathlib import Path
import platform
import yaml
import requests
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait, as_completed


def get_system():
    # global suffix
    platform = sys.platform
    if platform == 'win32':
        return "windows"
    elif "linux" in platform:
        return "linux"
    else:
        print("get system type error")
        exit(1)


def executor_callback(worker):
    logger.info("called worker callback function")
    worker_exception = worker.exception()
    result = worker.result()
    if worker_exception:
        print(worker_exception)
        # logger.exception("Worker return exception: {}".format(worker_exception))
    if result:
        print(result)


class Download:
    def __init__(self, proxy=None):
        self.download_path = "download_tmp"
        self.proxy = proxy
        self.tools_dict = {}
        self.rootpath = os.getcwd()
        self.pwd = os.path.dirname(os.path.abspath(__file__))
        self.ostype = platform.system().lower()
        self.suffix = ".exe" if "windows" == self.ostype else ""
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.tools_installed = {}
        self.getconfig()
        if os.path.exists(self.download_path) is False:
            os.makedirs(self.download_path)
        for k in self.tools_dict.keys():
            if self.tools_dict[k]['whetherdownload'] is True:
                self.tools_installed[k] = False

    def getconfig(self):
        # ostype = platform.system().lower() #get_system()
        toolsyaml_path = f"{self.rootpath}/config/tools_{self.ostype}.yaml"
        # toolsyaml_path = "tools_linux.yaml"
        if os.path.exists(toolsyaml_path):
            with open(toolsyaml_path, 'r', encoding='utf-8') as f:
                msg = yaml.load(f, Loader=yaml.FullLoader)['download']
                classify = ['domain', 'finger', 'portscan', 'sensitiveinfo', 'vulscan']
                # classify = ['portscan']
                for i in classify:
                    self.tools_dict.update(msg[i])
                    # {'amass': {'link': 'https://github.com/OWASP/Amass/releases/download/v3.20.0/amass_windows_amd64.zip',
                    #            'toolname': 'amass',
                    #            'topath': ['core/tools/domain/amass/',
                    #                       'amass/'],
                    #            'whetherdownload': True}
            # pprint(self.tools_dict)
        else:
            logger.error(f"[-] not found {toolsyaml_path}")
            logger.error("Exit!")
            exit(1)
            
    def unzipfile(self, filename, dirs="."):
        # if os.path.splitext(filename)[1] == ".zip":
        if os.path.exists(dirs) is False:
            os.makedirs(dirs)
        if zipfile.is_zipfile(filename):
            zf = zipfile.ZipFile(filename, 'r')
            zf.extractall(path=dirs)
            zf.close()
            logger.info(f"[+] unzip {filename} success.")
        elif tarfile.is_tarfile(filename):
            t = tarfile.open(filename)
            t.extractall(path=dirs)
            t.close()
            logger.info(f"[+] untar {filename} success.")
        # elif py7zr.is_7zfile(filename):
        #     with py7zr.SevenZipFile(filename, mode='r') as z:
        #         z.extractall(path=dirs)
        elif os.path.splitext(filename)[1] in ["", ".exe", ".db", ".7z"]:
            shutil.copy(filename, dirs)
        else:
            logger.error(f"[-] unzip {filename} to {dirs}failed.")
            return

    def downloadfile(self, url, dst_file, dst_path='download'):
        # dst_file = os.path.split(url)[1]
        target_filename = f'{dst_path}/{dst_file}'
        # if os.path.exists(dst_path) is False:
        #     os.makedirs(dst_path)
        if os.path.exists(target_filename) is False:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"}
                proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
                response = requests.get(url, headers=headers, proxies=proxies, stream=True)
                # response = requests.get(url, headers=headers, stream=True)
                handle = open(target_filename, "wb")
                for chunk in response.iter_content(chunk_size=512):
                    if chunk:  # filter out keep-alive new chunks
                        handle.write(chunk)
                handle.close()
                logger.info(f"[+] Download {dst_file} success.")
                # self.unzipfile(target_filename,dst_path)
                return target_filename
            except Exception as e:
                # print(e)
                logger.error(e)
                # logger.error(traceback.format_exc())
                logger.error(f"[-] Download {dst_file} fail!")
                return False
        else:
            logger.info(f"[*] {target_filename} already exists. Skip download.")
            return target_filename

    # def move(self,srcfile,dst_path):
    #     if os.path.exists(srcfile):
    #         if os.path.exists(dst_path):
    #             os.makedirs(dst_path)
    #         shutil.move(srcfile,dst_path)

    def handle(self, toolinfo):
        installflag = False
        try:
            if toolinfo['whetherdownload']:
                tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"
                # dis whether exist
                if os.path.exists(tool_filename) is False:
                    installflag = True
                else:  # exists
                    # print("tool_filename:",tool_filename)
                    if os.path.isdir(tool_filename):
                        tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}/{toolinfo['tool_main_filename']}"
                        if os.path.exists(tool_filename) is False:
                            installflag = True
                            shutil.rmtree(f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")  # rename
                        else:
                            installflag = False
                    else:  # not dir
                        installflag = False
                # installflag is True-> install tools
                if installflag is True:
                    zip_path = self.downloadfile(url=toolinfo['link'], dst_file=toolinfo['downloadfile'],
                                                 dst_path=self.download_path)
                    time.sleep(2)
                    if zip_path:
                        # if os.path.exists(f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"):
                        self.unzipfile(filename=zip_path, dirs=toolinfo['topath'][0])
                        time.sleep(2)
                        if toolinfo['source_name'] != toolinfo['final_name']:
                            # shutil.move(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}",f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                            os.rename(f"{os.getcwd()}/{toolinfo['topath'][0]}/{toolinfo['source_name']}",
                                      f"{os.getcwd()}/{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                            # os.remove(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}")
                        self.tools_installed[toolinfo['toolname']] = True
                else:
                    self.tools_installed[toolinfo['toolname']] = True
                    logger.info(f"[*] {tool_filename} already exists. Skip download and unzip.")
                # 赋权
                if "linux" in sys.platform:
                    tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"
                    if os.path.exists(tool_filename) is True:
                        if os.path.isdir(tool_filename):
                            tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}/{toolinfo['tool_main_filename']}"
                            if os.path.exists(tool_filename) is True:
                                os.system(f"chmod +x {tool_filename}")
                                logger.info(f"[+] chmod +x {tool_filename} success!")
                            else:
                                logger.error(f"[-] {tool_filename} non-existent, chmod +x {tool_filename} failed!")
                        else:  # not dir
                            os.system(f"chmod +x {tool_filename}")
                            logger.info(f"[+] chmod +x {tool_filename} success!")
                    else:
                        logger.error(f"[-] {tool_filename} non-existent, chmod +x {tool_filename} failed!")
        except KeyboardInterrupt:
            return False

    def tools_init(self):
        if os.path.exists(f"core/tools/vulscan/vulmap/module/licenses"):
            if os.path.exists(f"core/tools/vulscan/vulmap/module/licenses/licenses.txt") is False:
                shutil.copy("config/supplementary_files/vulmap/licenses.txt",
                            "core/tools/vulscan/vulmap/module/licenses")
                logger.info(f"[+] {self.rootpath}/core/tools/vulscan/vulmap/vulmap.py initialization is complete")
        if os.path.exists(f"core/tools/vulscan/goon/goon{self.suffix}"):
            os.system(os.path.realpath(f"{self.rootpath}/core/tools/vulscan/goon/goon{self.suffix}"))
            logger.info(f"[+] {self.rootpath}/core/tools/vulscan/goon/goon{self.suffix} initialization is complete")
        if os.path.exists(f"core/tools/vulscan/afrog/afrog{self.suffix}"):
            os.system(f"{self.rootpath}/core/tools/vulscan/afrog/afrog{self.suffix}")
            logger.info(f"[+] {self.rootpath}/core/tools/vulscan/afrog/afrog{self.suffix} initialization is complete")

    def run(self):
        flag = 0
        all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        # done,notdone = wait(all_task, return_when=ALL_COMPLETED)
        for future in as_completed(all_task):
            try:
                result = future.result()
            except Exception as e:
                logger.exception(f"ThreadPoolExecutor:\n{e}")
                print(e)
                # logger.error(f"ThreadPoolExecutor:\n{e}")
            # else:
            #     print(result)
        # time.sleep(5)
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")
        self.tools_init()

    def run1(self):
        flag = 0
        all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        try:
            while not list(reversed(all_task))[0].done():
                time.sleep(2)
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
            for task in reversed(all_task):
                task.cancel()
        # time.sleep(5)
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")

    def run2(self):
        flag = 0
        for tinfo in self.tools_dict.values():
            self.handle(tinfo)
        # all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        # done,notdone = wait(all_task, return_when=ALL_COMPLETED)
        # time.sleep(5)
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")


if __name__ == '__main__':
    dd = Download()
    dd.run()
