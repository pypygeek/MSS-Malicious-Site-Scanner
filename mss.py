from urllib import response
import requests
import re

domain ='https://dojang.io/mod/page/view.php?id=2293'

def mal_checker(suspect_url):
    """ 악성 진단 함수 """
    target_url = requests.get(suspect_url)
    target_url_data = target_url.text
    print(target_url_data)

    # TODO YARA 연동하기


try:
    all_url = []
    src_url = []
    
    response = requests.get(domain)
    
    #200 success code
    if response.status_code==200:
        response_data = response.text

        # TODO : URL 추출 부분 함수로 구현하기

        url_pattern = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-@\.&+:/?=]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', response_data)
        src_pattern = re.findall(r"(?:data-full-resolution|src|href|data)=\"(/.*?)\"", response_data)

        if not src_pattern:
            print('src does not exist.')
        else:
            for temp in src_pattern:
                src_url.append(domain+temp)

        all_url.append(url_pattern)
        all_url.append(src_url)
        
        # 2차원 리스트 1차원 리스트로 변환
        all_url_conversion = sum(all_url, [])

        # 중복 제거
        all_url_deduplication = list(dict.fromkeys(all_url_conversion))
        url_list = '\n'.join(all_url_deduplication)

        if not all_url_deduplication:
            print('url does not exist.')
        else:
            for url_single in all_url_deduplication:
                print(url_single)
                mal_checker(url_single)

    else:
        print(f"페이지 상태를 확인해세요. STATUS CODE :  {response.status_code}")
except:
    pass