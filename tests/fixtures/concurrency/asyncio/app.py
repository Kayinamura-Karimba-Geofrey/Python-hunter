"""Asyncio test fixture."""

import asyncio

async def fetch_data(url: str):
    await asyncio.sleep(1)
    return f"data from {url}"

async def main():
    t1 = asyncio.create_task(fetch_data("http://a.com"))
    t2 = asyncio.create_task(fetch_data("http://b.com"))
    res = await asyncio.gather(t1, t2)
    return res
