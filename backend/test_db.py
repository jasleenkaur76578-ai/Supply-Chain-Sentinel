import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def main():
    e = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with e.connect() as conn:
        res = await conn.execute(text("SELECT 42"))
        print("SQLAlchemy Async Engine Working! Result:", res.scalar())
    await e.dispose()

if __name__ == "__main__":
    asyncio.run(main())
