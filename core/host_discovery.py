"""
VulnForge Host Discovery
A lightweight "is this host alive" sweep, meant to run before a full scan
of a large CIDR range so time isn't spent running nmap/web/ssl modules
against hosts that never answer. Two independent probes, either one
counting as "alive":

  1. ICMP echo via the OS 'ping' command (works without raw-socket
     privileges on Windows; may need CAP_NET_RAW / root on Linux, and
     silently reports "down" there if it can't send one — which is why
     probe 2 exists).
  2. A TCP connect attempt against a short list of commonly-open ports.

This is deliberately not a full nmap -sn ARP/ICMP sweep (that needs root
and only works on a local subnet) — it's a portable, best-effort filter,
not a replacement for the per-host port scan that follows.
"""
import asyncio
import logging
import platform
import socket

logger = logging.getLogger("vulnforge.host_discovery")

COMMON_PROBE_PORTS = [80, 443, 22, 3389, 445, 21, 25, 53, 8080]


async def _ping_alive(host: str, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
        return rc == 0
    except Exception as exc:
        logger.debug(f"ping probe failed for {host}: {exc}")
        return False


async def _tcp_alive(host: str, ports: list[int], timeout: float) -> bool:
    async def try_port(port: int) -> bool:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    results = await asyncio.gather(*[try_port(p) for p in ports], return_exceptions=True)
    return any(r is True for r in results)


async def is_alive(host: str, timeout: float = 1.5, ports: list[int] | None = None) -> bool:
    """True if the host answers ICMP ping or accepts a TCP connect on any probe port."""
    try:
        socket.inet_aton(host)  # noqa: validates IPv4 quickly; hostnames fall through
    except OSError:
        pass  # hostname or IPv6 — still fine, just not pre-validated here

    ping_task = asyncio.create_task(_ping_alive(host, timeout))
    tcp_task = asyncio.create_task(_tcp_alive(host, ports or COMMON_PROBE_PORTS, timeout))
    done = await asyncio.gather(ping_task, tcp_task, return_exceptions=True)
    return any(r is True for r in done)


async def sweep(hosts: list[str], timeout: float = 1.5, concurrency: int = 64) -> dict[str, bool]:
    """Check many hosts concurrently (bounded). Returns {host: alive}."""
    sem = asyncio.Semaphore(concurrency)

    async def check(h: str) -> tuple[str, bool]:
        async with sem:
            return h, await is_alive(h, timeout)

    results = await asyncio.gather(*[check(h) for h in hosts])
    return dict(results)
