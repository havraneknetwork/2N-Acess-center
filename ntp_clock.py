import ipaddress
import re
import socket
import struct
import time


NTP_PORT = 123
NTP_UNIX_EPOCH_OFFSET = 2_208_988_800
NTP_PACKET_SIZE = 48
NTP_FRACTION_SCALE = 1 << 32
MAX_APPLICATION_CLOCK_OFFSET_SECONDS = 300


def normalize_ntp_server(server: str) -> str:
    if not isinstance(server, str):
        raise ValueError("Zadejte název nebo IP adresu NTP serveru.")

    value = server.strip()
    if not value:
        return ""
    if len(value) > 253:
        raise ValueError("Adresa NTP serveru je příliš dlouhá.")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    hostname = value.rstrip(".")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Zadejte platný název NTP serveru.") from error

    labels = hostname.split(".")
    if not hostname or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Zadejte platný název NTP serveru.")
    return hostname


def _ntp_timestamp_to_unix(value: bytes) -> float:
    seconds, fraction = struct.unpack("!II", value)
    return seconds - NTP_UNIX_EPOCH_OFFSET + fraction / NTP_FRACTION_SCALE


def query_ntp_server(server: str, timeout: float = 2.0) -> dict:
    server = normalize_ntp_server(server)
    if not server:
        raise ValueError("NTP server není nastaven.")

    addresses = socket.getaddrinfo(
        server,
        NTP_PORT,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
    )
    if not addresses:
        raise OSError("NTP server se nepodařilo přeložit na IP adresu.")

    last_error = None
    for family, socktype, proto, _, address in addresses[:4]:
        packet = bytearray(NTP_PACKET_SIZE)
        packet[0] = 0x23
        now = time.time()
        whole_seconds = int(now)
        fractional_seconds = now - whole_seconds
        transmit_stamp = struct.pack(
            "!II",
            whole_seconds + NTP_UNIX_EPOCH_OFFSET,
            int(fractional_seconds * NTP_FRACTION_SCALE),
        )
        packet[40:48] = transmit_stamp
        sent_at = _ntp_timestamp_to_unix(transmit_stamp)

        try:
            with socket.socket(family, socktype, proto) as client:
                client.settimeout(timeout)
                client.connect(address)
                client.sendall(packet)
                response = client.recv(NTP_PACKET_SIZE)
                received_at = time.time()
        except OSError as error:
            last_error = error
            continue

        if len(response) < NTP_PACKET_SIZE:
            last_error = OSError("NTP server vrátil neúplnou odpověď.")
            continue

        leap_indicator = response[0] >> 6
        version = (response[0] >> 3) & 0x7
        mode = response[0] & 0x7
        stratum = response[1]
        if leap_indicator == 3 or version not in (3, 4) or mode != 4 or not 1 <= stratum <= 15:
            last_error = OSError("NTP server nevrátil platný synchronizovaný čas.")
            continue
        if response[24:32] != transmit_stamp:
            last_error = OSError("NTP odpověď neodpovídá odeslanému požadavku.")
            continue

        server_received_at = _ntp_timestamp_to_unix(response[32:40])
        server_transmitted_at = _ntp_timestamp_to_unix(response[40:48])
        if server_received_at <= 0 or server_transmitted_at <= 0:
            last_error = OSError("NTP server vrátil neplatné časové značky.")
            continue
        offset = (
            (server_received_at - sent_at)
            + (server_transmitted_at - received_at)
        ) / 2
        if abs(offset) > MAX_APPLICATION_CLOCK_OFFSET_SECONDS:
            last_error = OSError(
                "Odchylka NTP překračuje bezpečný limit 5 minut; opravte systémový čas hostitele."
            )
            continue
        round_trip = (
            (received_at - sent_at)
            - (server_transmitted_at - server_received_at)
        )
        return {
            "offset_seconds": offset,
            "round_trip_seconds": max(0.0, round_trip),
            "stratum": stratum,
        }

    if last_error:
        raise OSError(f"NTP server {server} neodpovídá: {last_error}") from last_error
    raise OSError(f"NTP server {server} neodpovídá.")
