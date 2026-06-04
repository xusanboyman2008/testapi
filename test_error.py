import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

async def main():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/auth/register", json={"email": "newuser4@example.com", "password": "password"})
        print(response.status_code)
        print(response.text)

asyncio.run(main())
