import argparse
import subprocess
import json
from urllib.request import urlopen
import re

ip_v4format = re.compile(r"[\d{1-3}.\d{1-3}.\d{1-3}.\d{1-3}]+")
ip_v6format = re.compile(r"[\d*a-zA-Z*:]{1,}")
domain_name_format = re.compile(r"(\w+.\w+)")
local_ip = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255')
]


def version4(title: str):
    """Проверяем версию полученного IP-адреса"""
    check = title.split(' ')[-1][1:-1]
    ip = re.findall(ip_v4format, check)
    return len(ip[-1]) > 7


def find_AS(ip: str, count: int) -> list:
    """Получаем информацию о IP-адресе(AS, страна, провайдер)"""
    reply = urlopen("https://ipinfo.io/" + ip + "/json")
    data = json.load(reply)
    if 'org' in data.keys():
        as_info = data['org'].split(' ')[0]
        provider = ' '.join(data['org'].split(' ')[1:])
        country = data['country']
    else:
        as_info = 'Not available'
        provider = 'Not available'
        country = 'Not available'
    return [count, ip, as_info, country, provider]


def find_ip(data: list, container: list, ip_version: re.Pattern):
    """Извлекаем адреса из полученных после выполнения команды данных"""
    for line in data:
        if line != '':
            ip = re.findall(ip_version, line)
            if len(ip) > 0 and len(ip[-1]) > 7:
                container.append(ip[-1])


def is_local(ip: str):
    """Проверяем, относится ли IP-адрес к серым адресам"""
    for tup in local_ip:
        return tup[0] < ip < tup[1]


def print_table(table: list):
    print(f"Вами введен:{table[0]}".format())
    print("Номер | IP | AS | Country | Provider")
    for line in table[1:-1]:
        print(f'{line[0]} | {line[1]} | {line[2]} | {line[3]} | {line[4]}'.format())


def tracert(address: str):
    table = [address]
    ip_bin = []
    data = subprocess.check_output(["tracert", address],
                                   encoding='cp866').splitlines()

    if version4(data[1]):
        find_ip(data, ip_bin, ip_v4format)
    else:
        find_ip(data, ip_bin, ip_v6format)

    ip_bin = ip_bin[1:]
    count = 0
    for ip in ip_bin:
        count += 1
        if not is_local(ip):
            table.append(find_AS(ip, count))
        else:
            table.append([count, ip, '-', '-', '-'])

    print_table(table)
    table.clear()
    ip_bin.clear()


def main():
    parser = argparse.ArgumentParser("Tracer")
    parser.add_argument(
        "destination",
        metavar="(IP or host name)",
        type=str,
        help="Enter willing IP or host name")
    arg = parser.parse_args()
    tracert(arg.destination)


if __name__ == "__main__":
    main()
