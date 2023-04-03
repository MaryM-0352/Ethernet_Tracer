import sys
import subprocess
import json
from urllib.request import urlopen
import re

ip_v4format = re.compile(r"[\d{1-3}.\d{1-3}.\d{1-3}.\d{1-3}]+")
ip_v6format = re.compile(r"[\d*a-zA-Z*:]{1,}")
domain_name_format = re.compile(r"(\w+.\w+)")


def version4(title: str):
    'Проверяем версию полученного IP-адреса'
    check = title.split(' ')[-1][1:-1]
    myth = re.findall(ip_v4format, check)
    return len(myth[-1]) > 7


def find_AS(ip: str, count: int) -> list:
    'Получаем информацию о IP-адресе(AS, страна, провайдер)'
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
    'Извлекаем адреса из полученных после выполнения команды данных'
    for line in data:
        if line != '':
            ip = re.findall(ip_version, line)
            if len(ip) > 0 and len(ip[-1]) > 7:
                container.append(ip[-1])


def print_table(table: list):
    print(table[0])
    print("Номер" + 5*" " + "|" + "IP" + 40*" " + "|" + "AS" + 20*" " + "|" + "Country" + 8*" " + "|" + "Provider")
    for line in table[1:]:
            string = [str(point) + 10*" " + "|" for point in line]
            print("".join(string))


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
        table.append(find_AS(ip, count))

    print_table(table)
    table.clear()
    ip_bin.clear()


def main():
    args = sys.argv[1:]
    for name in args:
        tracert(name)


if __name__ == "__main__":
    main()



