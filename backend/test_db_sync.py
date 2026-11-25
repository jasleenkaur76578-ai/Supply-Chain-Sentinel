from sqlalchemy import create_engine, text

def main():
    e = create_engine("sqlite:///./sentinel_sync.db")
    with e.connect() as conn:
        res = conn.execute(text("SELECT 100"))
        print("Synchronous SQLite works instantly! Result:", res.scalar())
    e.dispose()

if __name__ == "__main__":
    main()
