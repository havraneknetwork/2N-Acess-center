import socket
import struct
import unittest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from unittest.mock import patch

from ntp_clock import NTP_FRACTION_SCALE, NTP_UNIX_EPOCH_OFFSET, normalize_ntp_server, query_ntp_server


class FakeNtpSocket:
    def __init__(self, response_factory):
        self.response_factory = response_factory

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, _timeout):
        pass

    def connect(self, _address):
        pass

    def sendall(self, packet):
        self.packet = packet

    def recv(self, _size):
        return self.response_factory(self.packet)


class NtpClockTests(unittest.TestCase):
    def test_normalizes_ip_and_hostname(self):
        self.assertEqual(normalize_ntp_server("192.0.2.1"), "192.0.2.1")
        self.assertEqual(normalize_ntp_server(" Time.Example.COM. "), "time.example.com")
        self.assertEqual(normalize_ntp_server(""), "")

    def test_rejects_urls_and_invalid_hostnames(self):
        for value in ("https://time.example", "time.example:123", "bad host", "x/" * 130):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ntp_server(value)

    def test_prague_timezone_switches_between_standard_and_daylight_time(self):
        prague = ZoneInfo("Europe/Prague")
        winter = datetime(2026, 1, 15, 12, tzinfo=timezone.utc).astimezone(prague)
        summer = datetime(2026, 7, 15, 12, tzinfo=timezone.utc).astimezone(prague)

        self.assertEqual(winter.utcoffset().total_seconds(), 3600)
        self.assertEqual(summer.utcoffset().total_seconds(), 7200)

    def test_queries_ntp_offset(self):
        unix_time = 1_798_000_000.0
        offset_seconds = 2.5

        def make_response(request):
            response = bytearray(48)
            response[0] = 0x24
            response[1] = 2
            response[24:32] = request[40:48]

            request_seconds, request_fraction = struct.unpack("!II", request[40:48])
            request_time = (
                request_seconds - NTP_UNIX_EPOCH_OFFSET
                + request_fraction / NTP_FRACTION_SCALE
            )
            server_receive = request_time + offset_seconds
            server_transmit = server_receive + 0.001

            def encode(timestamp):
                seconds = int(timestamp)
                fraction = int((timestamp - seconds) * NTP_FRACTION_SCALE)
                return struct.pack(
                    "!II",
                    seconds + NTP_UNIX_EPOCH_OFFSET,
                    fraction,
                )

            response[32:40] = encode(server_receive)
            response[40:48] = encode(server_transmit)
            return response

        fake_socket = FakeNtpSocket(make_response)
        with (
            patch("ntp_clock.socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("192.0.2.123", 123))
            ]),
            patch("ntp_clock.socket.socket", return_value=fake_socket),
            patch("ntp_clock.time.time", side_effect=[unix_time, unix_time + 0.01]),
        ):
            result = query_ntp_server("time.example")

        self.assertAlmostEqual(result["offset_seconds"], offset_seconds, places=2)
        self.assertEqual(result["stratum"], 2)


if __name__ == "__main__":
    unittest.main()
