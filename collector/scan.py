import sqlite3
import time

from core.db import init_db, insert_event


PIHOLE_DB = "/etc/pihole/pihole-FTL.db"


last_id = 0


def fetch():

    global last_id

    conn = sqlite3.connect(PIHOLE_DB)
    cur = conn.cursor()

    cur.execute("""
    SELECT id, domain, client
    FROM queries
    WHERE id > ?
    ORDER BY id ASC
    LIMIT 200
    """,
    (last_id,))


    rows = cur.fetchall()

    conn.close()


    return rows



def main():

    global last_id

    init_db()

    print("Collector running...")


    while True:

        data = fetch()


        for query_id, domain, device in data:

            last_id = max(last_id, query_id)

            insert_event(
                device,
                domain,
                time.time()
            )

            print(
                f"INGESTED: {device} -> {domain}"
            )


        time.sleep(2)



if __name__ == "__main__":
    main()
