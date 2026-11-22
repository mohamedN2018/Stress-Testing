"""Tiny authoritative DNS server (UDP, 127.0.0.1) for tests of DNS-based checks."""

from __future__ import annotations

import socket
import threading

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


class FakeDnsServer:
    """Answers from a dict: {(name, record type): [record text, ...]}; everything else is NXDOMAIN."""

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = {(name.rstrip(".").lower(), rtype.upper()): values for (name, rtype), values in records.items()}
        self.queries: list[tuple[str, str]] = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.2)
        self.port = self._socket.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, name="fake-dns", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._running:
            try:
                data, address = self._socket.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            try:
                query = dns.message.from_wire(data)
                question = query.question[0]
                name = question.name.to_text().rstrip(".").lower()
                rtype = dns.rdatatype.to_text(question.rdtype)
                self.queries.append((name, rtype))
                response = dns.message.make_response(query)
                values = self.records.get((name, rtype))
                if values:
                    response.answer.append(dns.rrset.from_text(question.name, 60, "IN", rtype, *values))
                else:
                    response.set_rcode(dns.rcode.NXDOMAIN)
                self._socket.sendto(response.to_wire(), address)
            except Exception:  # noqa: BLE001 - malformed test query: ignore
                continue

    def stop(self) -> None:
        self._running = False
        self._thread.join(2)
        self._socket.close()
