from urllib import response
import requests
import re
import yara

domain =''

def mal_checker(suspect_url):
    """ 악성 진단 함수 """
    target_url = requests.get(suspect_url)
    target_url_data = target_url.text

    # TODO YARA 연동하기
    rule = yara.compile(source='rule html_test: test {strings: $a = "html" condition: $a}')
    matches = rule.match(data=target_url_data)
    print(f"{suspect_url} -> {matches}" )

try:
    all_url = []
    src_url = []
    
    response = requests.get(domain)
    
    # 200 success code
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

        if not all_url_deduplication:
            print('url does not exist.')
        else:
            for url_single in all_url_deduplication:
                # 특정 문자열 제거
                url_single= ''.join( x for x in url_single if x not in ')')
                mal_checker(url_single)
    else:
        print(f"페이지 상태를 확인해세요. STATUS CODE :  {response.status_code}")
except:
    pass