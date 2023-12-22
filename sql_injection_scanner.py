
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"



def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details



def is_vulnerable(response):
    """ function to check whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url):
    try:
        # test on URL
        for c in "\"'":
            # add quote/double quote character to the URL
            new_url = f"{url}{c}"
            print("[!] Trying", new_url)
            # make the HTTP request
            res = s.get(new_url)
            if is_vulnerable(res):
                # SQL Injection detected on the URL itself, 
                # no need to preceed for extracting forms and submitting them
                print("vuln deteected")
                return("SQL Injection: Vulnerability detected")
            elif is_vulnerable(res):
                print("vuln not det")
                return("SQL Injection: Vulnerability NOT detected")
                
        # test on HTML forms
        forms = get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = get_form_details(form)
            for c in "\"'":
                # the data body we want to submit
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        data[input_tag["name"]] = f"test{c}"
                # join the url with the action (form request URL)
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = s.post(url, data=data)
                elif form_details["method"] == "get":
                    res = s.get(url, params=data)
                # test whether the resulting page is vulnerable
                if is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    return ("SQL Injection: Vulnerability detected")
                    
        print("not vulnerable")
        return ("SQL Injection: Vulnerability Not detected")
    except:
        
        return ("")

if __name__ == "__main__":
    url = "www.padmashalisevasamajam.org/pss/"
    scan_sql_injection(url)
    





#https://xss-game.appspot.com/level1/frame
    a = scan_sql_injection("http://www.padmashalisevasamajam.org/pss/")
    print(a)

#http://testphp.vulnweb.com/artists.php?artist=1




"""
https://fairpartstead.live/nfferfnu/?utm_campaign=pEv9cTd8QNHYzqqr5UNFx2COHvnp_
JE3r8uVIhm3Qww1&t=main7d&f=1&sid=t4~pjkmca14l4g2vg3a4a0u4rwd&fp=rDeLiLmKxvqeCZJv
7EOJujCj%2B7Q%2FzfdJzsSq1YG9ii1TTHA9MwAPccfDLzmc572YRRwkPl1Z%2FejTZA6SBu%2BxMlLdOB
faf%2FmucaIFks15ZGIfkmHz11Z7TwpERA7P6q7Qvxs6P%2Bl5ANJefWEDWsukcSwTiLq%2Bukd2AfXM6iot
Q2A2G9ypqefauxtVX9MsjmrwELgvkhuYX3O4vCbfO3u3u%2BcgmxybSRMUAxQMIyOxZaJD5CbFb8u%2FNZFzxj
Vmb2na%2F2gLv6mw81WQQWEDrHIlbLCfHrqzgIsG2DOOPoBzTvdaUS0rfckCfUEuJky9GyC9wen0m%2FZWuhE
SuDnT7r%2F1t4VP7NQiQqrGNAxPSP3Js1mXwFQR6ETo6qNmB1Y9GlSSw03XMLjrFdG9RHikF6lPuLEbw6B06l
hi9fftAA7RtR4%2By%2Fu8c%2BsUI%2Bx686HBuOLMRl%2FRe5cgPfZuMQNyFK%2FxUkImK62P8p6P2XxBkog
BTa%2BGSQ8BoofYQ52DHykLQV1l7hT4vQUzgpKO2CYr%2B7qjdk%2FkiIMA7jazk9iO07%2FyWEUBSibAeA4X
N8PfWqW8%2BNVO8b5XOzBQ%2B6mTFm3Kk7u2EuNqgPmybHjPoXajZ8asoV86bLX2Qa5LXs7SqmRz16xlCWkDjU
kI79%2BzWu%2BhXuqu%2F94Wfb0HvN74IshBiouiwKrJH92dYDHb7JYi17DnpbPTLF1oIeuf%2Bo%2BowP73Yb
nIQfD%2FiOyYGHWMlmHrHQs%2BydxaWD7ium1RSh0%2FFPECR9aF6PBbtmhygPKw4QszU0QitVrs0toZ67uSCg
9Ncr4LlLa5ZMuySk5nJH0Ei%2Bh1EgAOilJyZXCrqVecdBxUfwXX1lNwEswnT3mTc%2Bn%2BwGBD5UGnsbCtES
Gr4nYC9smEKZ5wYUQyuwHAUyJU11N8Cdt02NJ%2BFcwAddHWK94r7BsH3jqV%2BDBMeRBjn7yEAnudPnMoiFTA
waimZZVk5if7D7CVq2devD9M2wjDD%2B2Y8%2B4XiB9xsCnQzuZhfCRKPlkWBN8sGVegIOg%2FHpF5W6X%2F1f
BM5qvfIgKvtBZ0RpG8DdmqfLuj40MQ1hp4cavP3Zv7Soq4MnOYl9xxCrPhKaVAJom6P4ObCnbmgkLtUA6srfp8
y7YnPauvtIZx7dJcGtmULfwntYW8sDEKSOAyQ8ywhPTY1V3Yp0OidbGexSq%2BUSP6ktvA14R1FtasQr%2FPj5
Pi27kvXZfivP6xjxRqXjY%2BqBq%2Baf1uOTXdVgpI1HxT1yRKsS0B6amMZDnouk7NxzpTLxi8XCOFdxyeDxjK
znogXitlp2PT9zMFJdhf8tEDF9Dublrdv%2Bmb7BkVgwg4%2Fg24a%2BKKJULrWLp82bk7DsBjaKUrvEqIE0Xa
7jk59z7%2FMqgnwdlxhDnTb%2FD4u8YSCh9kh7%2BZhdg71iVWNk6lf2bA7bcmLDFIDuVt4ukKfB%2BI41XnAk
N8BWSa9dL0sMFlrAd39R1fm%2BYT6eBRwOYNkVAjYzN%2FrTWfmORcXZgiux742RZAdKfxs8ulnm0OpopobfLw
dHIkmIkn6Pc%2Br48Q6S5S3OYHm%2BBdUoBRdYFdnwK74%2FySz%2BkpAhIVh1Nxn65r1lsiGVaQilmoRT3FM8
LgntNvops6obc6lObA9yZCEWz4JFCgoGAZyCNzOgkUxaZRpmgUmyCpnSjyyfL2ofO0fo1lh4XxrzkshvmCuZ%2
FSDWSz%2Bwmgs4NNTMeFLIgUG5eO%2BwVAEccAhc%2BT89764rZZp1TJGB7O53jORsSL9t1X08AvBQKLh6Sz3n
XdQzRnAv%2Fhtxwl1Ibp86JQTMzfNAotsv%2B40rLupQGmpc5Eidj93eNhCTlLFnZA5n15fkjX7hGvNFaveGA%
2BjI%2Bv7RYMY83OraD1TDyqtdERjgK4tJQfDZ2ED6LoNEQniWLCvlG%2FwVUY4MtQMyA6
"""