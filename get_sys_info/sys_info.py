# 获取操作系统信息
import json
import os
import platform
import re
import socket
import subprocess
from tzlocal import get_localzone


def get_os():
    """
    获取操作系统信息
    :return:
    """
    os_info = platform.platform()
    # print('操作系统信息:', os_info)
    return os_info


def get_host_name():
    """
    获取主机名称
    :return:
    """
    hostname = socket.gethostname()
    # print('主机名称:', hostname)
    return socket.gethostname()


def get_timezone():
    """
    获取时区信息
    :return:
    """
    # 输出时区信息
    localzone = get_localzone()
    # print("时区信息:", str(localzone))
    return str(localzone)


def get_linux_ips():
    """
    获取 linux 系统的ip地址列表
    :return:
    """

    ip_address_list = []

    # 使用 ifconfig 命令获取网络接口信息
    result = subprocess.run(['ifconfig', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output = result.stdout.decode("gbk")
    except Exception:
        output = result.stdout.decode("utf-8")

    # 使用正则表达式匹配 IP 地址信息
    pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    matches = re.findall(pattern, output)

    for match in matches:
        ip_address_list.append(match)
    # print(ip_address_list)
    return ','.join(ip_address_list)


def get_windows_ips():
    """
    获取 windows 系统的ip地址列表
    :return:
    """
    ip_address_list = []

    # 使用 ipconfig 命令获取网络接口信息
    result = subprocess.run(['ipconfig', '/all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output = result.stdout.decode("gbk")
    except Exception:
        output = result.stdout.decode("utf-8")

    # 使用正则表达式匹配 IPv4 地址信息
    pattern = r'(IPv4 地址|IPv4 Address)[\.\s]+:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    matches = re.findall(pattern, output)

    for match in matches:
        ip_address_list.append(match[1])
    # print(ip_address_list)
    return ','.join(ip_address_list)


def get_ip_address():
    if os.name == 'posix':  # 如果当前操作系统是 Linux
        return get_linux_ips()
    elif os.name == 'nt':  # 如果当前操作系统是 Windows
        return get_windows_ips()


def get_env_variable():
    """
    获取系统的环境变量
    :return:
    """
    env_vars = os.environ

    env_dict = {}
    for key in env_vars.keys():
        env_dict[key] = env_vars.get(key)

    return json.dumps(env_dict)


def get_linux_antivirus_info():
    """
    获取 linux 系统的杀毒软件
    :return:
    """
    antivirus_list = []

    # 检查 ClamAV 是否安装
    result = subprocess.run(['which', 'clamscan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        antivirus_list.append('ClamAV')

    # 检查 Sophos Anti-Virus 是否安装
    result = subprocess.run(['which', 'savscan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        antivirus_list.append('Sophos Anti-Virus')

    # 检查 F-Prot Antivirus 是否安装
    result = subprocess.run(['which', 'fpscan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        antivirus_list.append('F-Prot Antivirus')

    # 检查 Bitdefender Antivirus Scanner 是否安装
    result = subprocess.run(['which', 'bdscan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        antivirus_list.append('Bitdefender Antivirus Scanner')

    return ','.join(antivirus_list)


def get_windows_antivirus_info():
    """
    获取 windows 系统的杀毒软件
    :return:
    """
    antivirus_list = []
    command = 'powershell "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntivirusProduct"'
    check_output = subprocess.check_output(command, shell=True)
    try:
        output = check_output.decode("gbk")
    except Exception:
        output = check_output.decode("utf-8")

    for i in output.split(os.linesep):
        if i.strip().startswith('displayName'):
            strip = i.strip().split(':')[1].strip()
            antivirus_list.append(strip)
    return ','.join(antivirus_list)


def get_antivirus_info():
    if os.name == 'posix':  # 如果当前操作系统是 Linux
        return get_linux_antivirus_info()
    elif os.name == 'nt':  # 如果当前操作系统是 Windows
        return get_windows_antivirus_info()


def get_device_type():
    """
    获取设备类型
    :return:
    """
    return platform.machine()


def get_account_info():
    """
    获取账户权限
    :return:
    """
    if os.name == 'posix':  # 如果当前操作系统是 Linux
        username = os.getlogin()
        account_dict = {'username': username}
        # print('当前登录的用户名:', username)

        if os.geteuid() == 0:
            # print("当前用户具有 root 权限")
            account_dict['user_auth'] = '1'
            return json.dumps(account_dict)
        else:
            # print("当前用户没有 root 权限")
            account_dict['user_auth'] = '0'
            return json.dumps(account_dict)

    elif os.name == 'nt':  # 如果当前操作系统是 Windows
        import getpass
        import ctypes

        user = getpass.getuser()
        account_dict = {'username': user}
        # print("当前用户:", user)

        if ctypes.windll.shell32.IsUserAnAdmin():
            # print("当前用户具有管理员权限")
            account_dict['user_auth'] = '1'
            return json.dumps(account_dict)
        else:
            # print("当前用户没有管理员权限")
            account_dict['user_auth'] = '0'
            return json.dumps(account_dict)


def get_domain_info():
    if os.name == 'posix':  # 如果当前操作系统是 Linux
        # 对于 Linux 系统，可以使用 hostnamectl 命令来获取主机名和域名信息。具体来说，可以使用以下命令来获取计算机的域名：

        command = """hostnamectl | grep "Domain name" | awk '{print $3}'"""
        check_output = subprocess.check_output(command, shell=True)
        try:
            output = check_output.decode("gbk")
        except Exception:
            output = check_output.decode("utf-8")

        return output
        # 如果该计算机没有加入域，则该命令将不会返回任何输出。
    elif os.name == 'nt':  # 如果当前操作系统是 Windows
        import wmi

        c = wmi.WMI()

        # 获取计算机系统信息
        cs1 = c.Win32_ComputerSystem()[0]

        # 计算机所属域的名称，如果计算机不属于任何域，则返回工作组的名称。
        domain = cs1.Domain

        # 计算机在指定域工作组中的角色。独立工作站（0）、成员工作站（1）、独立服务器（2）、成员服务器（3）、备用域控制器（4）、主域控制器（5）
        domain_role = cs1.DomainRole

        # 如果为 True，则计算机是域的一部分。如果该值为 NULL，则计算机不属于任何域，或者状态未知。如果您将计算机从域中移除，则该值变为 false。
        part_of_domain = cs1.PartOfDomain

        # 此计算机的工作组名称。如果 PartOfDomain 属性的值为 False，则返回工作组的名称。
        work_group = cs1.Workgroup

        domain_dict = {'domain': domain, 'domain_role': domain_role, 'part_of_domain': part_of_domain,
                       'work_group': work_group}
        domain_json = json.dumps(domain_dict)
        # print(domain_json)
        return domain_json


def get_info():
    info_dict = {'os': get_os(), 'account_info': get_account_info(), 'device_type': get_device_type(),
                 'host_name': get_host_name(), 'ip_address': get_ip_address(), 'timezone': get_timezone(),
                 'env_variable': get_env_variable(), 'antivirus_info': get_antivirus_info(),
                 'domain_info': get_domain_info()}
    info_json = json.dumps(info_dict)
    return info_json
