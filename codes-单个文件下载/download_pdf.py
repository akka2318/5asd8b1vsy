import base64
import binascii
import json
import os
import re
import shutil
import sys
from urllib.parse import urlparse, parse_qs

import fitz
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from requests.auth import HTTPBasicAuth
import AES_decryption

headers = {
    "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "^Cookie": "__root_domain_v=.ipmph.com; _qddaz=QD.601623259853031; sensorsdata2015jssdkcross=^%^7B^%^22distinct_id^%^22^%^3A^%^22191375332ee45b-02b45bdd71fd0ce-4c657b58-1024000-191375332ef499^%^22^%^2C^%^22first_id^%^22^%^3A^%^22^%^22^%^2C^%^22props^%^22^%^3A^%^7B^%^22^%^24latest_traffic_source_type^%^22^%^3A^%^22^%^E7^%^9B^%^B4^%^E6^%^8E^%^A5^%^E6^%^B5^%^81^%^E9^%^87^%^8F^%^22^%^2C^%^22^%^24latest_search_keyword^%^22^%^3A^%^22^%^E6^%^9C^%^AA^%^E5^%^8F^%^96^%^E5^%^88^%^B0^%^E5^%^80^%^BC_^%^E7^%^9B^%^B4^%^E6^%^8E^%^A5^%^E6^%^89^%^93^%^E5^%^BC^%^80^%^22^%^2C^%^22^%^24latest_referrer^%^22^%^3A^%^22^%^22^%^7D^%^2C^%^22identities^%^22^%^3A^%^22eyIkaWRlbnRpdHlfYW5vbnltb3VzX2lkIjoiMTkxMzc1MzMyZWU0NWItMDJiNDViZGQ3MWZkMGNlLTRjNjU3YjU4LTEwMjQwMDAtMTkxMzc1MzMyZWY0OTkiLCIkaWRlbnRpdHlfY29va2llX2lkIjoiMTkxM2E1NDlhYmJiYzAtMGE3MmViNDdmZDMwZC00YzY1N2I1OC0xMDI0MDAwLTE5MTNhNTQ5YWJjMjNhMCJ9^%^22^%^2C^%^22history_login_id^%^22^%^3A^%^7B^%^22name^%^22^%^3A^%^22^%^22^%^2C^%^22value^%^22^%^3A^%^22^%^22^%^7D^%^2C^%^22^%^24device_id^%^22^%^3A^%^22191375332ee45b-02b45bdd71fd0ce-4c657b58-1024000-191375332ef499^%^22^%^7D^",
    "Pragma": "no-cache",
    "Referer": "https://z.ipmph.com/zzfwh5/",
    "Sec-Fetch-Dest": "image",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "^sec-ch-ua": "^\\^Not)A;Brand^^;v=^\\^99^^, ^\\^Microsoft",
    "sec-ch-ua-mobile": "?0",
    "^sec-ch-ua-platform": "^\\^Windows^^^",
    "Origin": "https://z.ipmph.com",
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "referer": "https://z.ipmph.com/zzfwh5/",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "Access-Control-Request-Headers": "content-type",
    "Access-Control-Request-Method": "POST",
    "Content-Type": "application/json",
    "priority": "u=1, i",
    "upgrade-insecure-requests": "1",
    "origin": "https://z.ipmph.com",
    "range": "bytes=0-",
    "access-control-request-headers": "content-type",
    "access-control-request-method": "POST",
    "content-type": "application/json",
    "Referer;": ""
}


# 分析url，获得相应数据：文件标识符，个数，每个pdf页数
def get_total_and_key_url(url):
    # 获得文件标识符
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    route_query_url = query_params.get("url", [None])[0]
    if route_query_url:
        parsed_route_url = urlparse(route_query_url)
        file_identifier = parsed_route_url.path.split('/')[-1]
    else:
        file_identifier = None

    # 构造获取密文的网站，并获取密文
    url_key = f'https://bzyxz.ipmph.com/pdf/{file_identifier}/{file_identifier}.js'
    response = requests.get(url_key)
    match = re.search(r'window\.openKey="([^"]+)"', response.text)
    decoded_bytes = base64.b64decode(match.group(1))

    # base64解密后使用aes解密，CBC，None
    hex_str = binascii.hexlify(decoded_bytes).decode('utf-8')
    hex_str = binascii.unhexlify(hex_str)
    key = b'1030110301123456'
    iv = b'1234567890123456'
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(hex_str) + decryptor.finalize()
    # 转化字符串
    decrypted_data = decrypted_data.decode('utf-8')

    # 获取文件个数，每10页为一个
    total_value = query_params.get("total", [None])[0]
    page_size = query_params.get('pagesize', [None])[0]

    total_value = int(total_value)
    page_size = int(page_size)

    if total_value % page_size == 0:
        num = total_value // page_size
    else:
        num = total_value // page_size + 1

    return file_identifier, decrypted_data, num


# 进度条
def progress_bar(progress, total_, bar_length=50):
    percent = 100 * (progress / float(total_))
    bar = '=' * int(percent / (100 / bar_length)) + '-' * (bar_length - int(percent / (100 / bar_length)))
    sys.stdout.write('\r|%s| %d%%' % (bar, percent))
    sys.stdout.flush()


# 下载pdf文件
def download(count, password, url, name):
    path = os.path.join(os.getcwd(), name)
    path_new = path + "-new"
    if not os.path.exists(path_new):
        os.makedirs(path_new)
    if not os.path.exists(path):
        os.makedirs(path)

    progress = 1

    for i in range(count):

        response = requests.get(url.format(i), auth=HTTPBasicAuth('', password))
        with open(f'{path}/{i}.pdf', 'wb') as f:
            f.write(response.content)

        doc = fitz.open(f'{path}/{i}.pdf')

        if doc.authenticate(password):
            pass
        else:
            print("密码错误，无法解锁PDF文件")

        doc.save(f'{path_new}/{i}.pdf')
        doc.close()

        progress_bar(progress, count)
        progress += 1

    shutil.rmtree(path)
    os.rename(path_new, path)
    print()
    print('书本pdf下载完成，处理文件中')


# 合并文件，并添加书签
def merge_pdf_and_marker(title, ide, total):
    # 获取书签相关数据，并处理
    def get_bookmarker():
        url = f'https://bzyxz.ipmph.com/pdf/{ide}/{ide}_bookmarks.json'
        data_text = requests.get(url).text
        data = json.loads(data_text)

        def process_bookmark(item_, level=1):
            title_ = item_['title'].replace('\u3000', '  ').replace('\x00', '  ')
            page = item_['desPageNum']
            list_ml.append((level, title_, page))

            if 'subBookMark' in item_ and item_['subBookMark']:
                for sub_item in item_['subBookMark']:
                    process_bookmark(sub_item, level + 1)

        list_ml = []
        for item in data:
            process_bookmark(item)

        return list_ml

    file_path = title + 'pdf'
    file_path = os.path.abspath(file_path)
    out_path = os.path.abspath(title)
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    out_path = os.path.join(out_path, f'{title}.pdf')
    pdf_files = []
    for i in range(total):
        pdf_files.append(os.path.join(file_path, f'{i}.pdf'))

    # print(pdf_files)
    # return
    merged_pdf = fitz.open()

    # 合并PDF文件
    for i in pdf_files:
        temp_doc = fitz.open(i)
        merged_pdf.insert_pdf(temp_doc)

    merged_pdf.save(out_path)
    merged_pdf.close()

    # 书签
    doc = fitz.open(out_path)
    doc.set_toc(get_bookmarker())
    doc.saveIncr()

    print(f'\033[32m已经输出至：{out_path}\033[0m')


# 下载电子课本算法
def strat_download_book_pdf():
    bookid_ = AES_decryption.AES_Cipher()[0]

    response_pdf_url = requests.get(
        'https://zengzhi.ipmph.com/zhbooks/zzfw_web?command=bookDetail',
        params={'json': f'{{"bookId":"{bookid_}"}}'}).text
    # print(response_pdf_url)
    url_download = json.loads(response_pdf_url)['data']['getPdf']['url']
    title = json.loads(response_pdf_url)['data']['title']
    file_identifier, key, total = get_total_and_key_url(url_download)

    download(count=total,
             password=key,
             url=f'https://bzyxz.ipmph.com/pdf/{file_identifier}/{{}}_{file_identifier}.pdf',
             name=f'{title}pdf')

    merge_pdf_and_marker(title, file_identifier, total)

    shutil.rmtree(os.path.abspath(f'{title}pdf'))

while True:
    try:
        strat_download_book_pdf()
    except Exception as e:
        print(f'\033[31m{e}\033[0m')
# strat_download_book_pdf()
# merge_pdf_and_marker('卫生法（第6版）','bfe4801a8bc5489781740e555806efd5',32)
