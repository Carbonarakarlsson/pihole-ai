def block(domain):
    with open("blocklist.txt", "a") as f:
        f.write(domain + "\n")
