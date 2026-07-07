def alert(msg):
    print(f"\n🚨 ALERT: {msg}")

    with open("alerts.log", "a") as f:
        f.write(msg + "\n")
