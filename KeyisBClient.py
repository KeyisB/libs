"""
GW Client
************

 - mmbp

 - mmbps

*created by KeyisB*

-==============================-




Copyright (C) 2024 KeyisB. All rights reserved.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to use the Software exclusively for
projects related to the MMB or GW systems, including personal,
educational, and commercial purposes, subject to the following
conditions:

1. Copying, modification, merging, publishing, distribution,
sublicensing, and/or selling copies of the Software are
strictly prohibited.
2. The licensee may use the Software only in its original,
unmodified form.
3. All copies or substantial portions of the Software must
remain unaltered and include this copyright notice and these terms of use.
4. Use of the Software for projects not related to GW or
MMB systems is strictly prohibited.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

__GW_VERSION__ = "0.0.0.0.4"
__version__ = "1.1.4"

import re
import os
import httpx
import asyncio
from typing import List, Optional, Union, Literal, AsyncIterable
import logging as logging2
import urllib.parse
import tempfile
from concurrent.futures import ThreadPoolExecutor
from KeyisBLogging import logging

logging2.basicConfig(level=logging2.INFO)

class Exceptions:
    class ErrorConnection(Exception):
        """Ошибка подключения к серверу."""
        def __init__(self, message="Ошибка подключения к серверу"):
            super().__init__(message)
    
    class UnexpectedError(Exception):
        """Неожиданная ошибка при подключении к серверу."""
        def __init__(self, message="Неожиданная ошибка при подключении к серверу"):
            super().__init__(message)
    
    class ServerTimeoutError(Exception):
        """Тайм-аут подключения к серверу."""
        def __init__(self, message="Тайм-аут подключения к серверу"):
            super().__init__(message)
    
    class ServerAccessDeniedError(Exception):
        """Доступ к серверу отклонён."""
        def __init__(self, message="Доступ к серверу отклонён"):
            super().__init__(message)
    
    class ServerNotFoundError(Exception):
        """Сервер не найден."""
        def __init__(self, message="Сервер не найден"):
            super().__init__(message)
    
    class ServerFailureError(Exception):
        """Сбой на сервере."""
        def __init__(self, message="Сбой на сервере"):
            super().__init__(message)
    
    class InvalidServerResponseError(Exception):
        """Некорректный ответ от сервера."""
        def __init__(self, message="Некорректный ответ от сервера"):
            super().__init__(message)
    class DNS:
        class ErrorConnection(Exception):
            """Ошибка подключения к DNS-серверу."""
            def __init__(self, message="Ошибка подключения к DNS-серверу"):
                super().__init__(message)

        class UnexpectedError(Exception):
            """Неожиданная ошибка при работе с DNS."""
            def __init__(self, message="Неожиданная ошибка при работе с DNS"):
                super().__init__(message)

        class DNSServerNotFoundError(Exception):
            """DNS-сервер не найден."""
            def __init__(self, message="DNS-сервер не найден"):
                super().__init__(message)

        class DNSTimeoutError(Exception):
            """Таймаут при запросе к DNS-серверу."""
            def __init__(self, message="Таймаут при запросе к DNS-серверу"):
                super().__init__(message)

        class InvalidDNSError(Exception):
            """Неверный формат DNS-запроса."""
            def __init__(self, message="Неверный формат DNS-запроса"):
                super().__init__(message)

        class DNSResponseError(Exception):
            """Ошибка в ответе от DNS-сервера."""
            def __init__(self, message="Ошибка в ответе от DNS-сервера"):
                super().__init__(message)

        class DNSServerFailureError(Exception):
            """Отказ DNS-сервера."""
            def __init__(self, message="Отказ DNS-сервера"):
                super().__init__(message)

        class DNSAccessDeniedError(Exception):
            """Доступ к DNS-серверу запрещён."""
            def __init__(self, message="Доступ к DNS-серверу запрещён"):
                super().__init__(message)






class Url:
    def __init__(self, url_str: Optional[str] = None):
        self.interpreter: Optional[str] = None
        self.scheme: str = None # type: ignore
        self.hostname: str = None # type: ignore
        self.path: str = None # type: ignore
        self.query: str = None # type: ignore
        self.fragment: str = None # type: ignore
        self.params: dict = None # type: ignore

        if url_str:
            self.setUrl(url_str)
        
        

    def __parse_url(self, url_str: str):
        pattern = r"^(?P<interpreter>[A-Za-z0-9_]+):(?P<rest>[A-Za-z0-9_]+://.+)$"
        match = re.match(pattern, url_str)
        
        if match:
            interpreter = match.group("interpreter")
            rest_url = match.group("rest")
        else:
            interpreter = None
            rest_url = url_str
    
        parsed_url = urllib.parse.urlparse(rest_url)


        self.interpreter = interpreter
        self.scheme = parsed_url.scheme if parsed_url.scheme != '' else None # type: ignore

        self.hostname = parsed_url.netloc if parsed_url.netloc != '' else None # type: ignore
        self.path = parsed_url.path
        self.query = parsed_url.query
        self.fragment = parsed_url.fragment
        self.params = self.__parse_params(parsed_url.query)

    def __parse_params(self, query_str: str) -> dict:

        parsed = urllib.parse.parse_qs(query_str)
        cleaned = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        return cleaned

    def __str__(self):
        return self.getUrl()
    def setUrl(self, url_str: str):
        if url_str == '':
            url_str = '/'
        
        logging2.info(f"Parsed URL: [{url_str}]")
        self.__parse_url(url_str)
        

    def getUrl(self, parts: List[Literal['interpreter', 'scheme', 'hostname', 'path', 'params', 'fragment']] = ['scheme', 'hostname', 'path', 'params', 'fragment']) -> str:
        scheme = self.scheme if'scheme' in parts else ''
        hostname = self.hostname if 'hostname' in parts else ''
        params = urllib.parse.urlencode(self.params, doseq=True) if 'params' in parts else ''
        path = self.path if 'path' in parts else ''
        fragment = self.fragment if 'fragment' in parts else ''

        if scheme is None: scheme = ''
        if hostname is None: hostname = ''



        url = urllib.parse.urlunparse((
            scheme, hostname, path, '', params, fragment
        ))
        url = f'{self.interpreter}:{url}' if 'interpreter' in parts and self.interpreter is not None else url


        if 'path' not in parts:
            if url.endswith(':'):
                url = url[:-1]

        if 'scheme' not in parts:
            if url.startswith('//'):
                url = url[2:]

        
        return url
    def isSchemeSecure(self) -> bool:
        return self.scheme in ('https', 'mmbps')
    
    def getDafaultUrl(self) -> 'Url':
        _url = Url(self.getUrl())


        if _url.scheme in ('mmbp', 'mmbps'):
            with ThreadPoolExecutor() as executor:
                future = executor.submit(self.__run_asyncio_task_fetch_sync__, _url.hostname)
                result = future.result()
                _url.hostname = result
        if _url.scheme == 'mmbps': _url.scheme = 'https'

        return _url

        
            

    def __run_asyncio_task_fetch_sync__(self, hostname):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(Client.getDNS(hostname))
        finally:
            loop.close()
        return result



class _Client:
    def __init__(self):
        self.__servers = {}

        self.__root_dns_server = 'http://51.250.85.38:50000'
        self.addServer(self.__root_dns_server)

        self.__ca_crt = """
-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUZPOwLkKJSodBsrye8uGyCDfS2WswDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xDTALBgNVBAsMBFVuaXQxDTALBgNVBAMM
BE15Q0EwHhcNMjQxMDEzMDA0MTM4WhcNMzQxMDExMDA0MTM4WjBhMQswCQYDVQQG
EwJVUzEOMAwGA1UECAwFU3RhdGUxDTALBgNVBAcMBENpdHkxFTATBgNVBAoMDE9y
Z2FuaXphdGlvbjENMAsGA1UECwwEVW5pdDENMAsGA1UEAwwETXlDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0UapAmQ/6tQ5FGcqmCzs9E+plXK8J3
I+93urrqUAwmU8GVmEJHfHWid16HYK8qrUrDslVWwOS9Oz+7TcXRRvY9VihKdm0D
JS8ba0ry4xIX0tIXQ2+lpOhBQ9dyTcte5Ob049DNZrKWDiAtXgC4IF7MGNTtBPLj
abdKeHowxLzwbJIje3tHhFB6Haz5+xHHZdqU13uhmOd+HzXOIYOKoB3QeFCH91Ll
U9WXrxtjT8gNnyWMbiEjnifoPQISv2r2K284PaJhe+EnzH2HEclSS8mjlvvUn5pd
AOX4YM6q1BTGZRmswTOUHECDsFPcqOA8KO1b8AfVDcFSJgiL6Wdh71sCAwEAAaNT
MFEwHQYDVR0OBBYEFPLj7vlEwwzgRNM61uRpU41K+kfjMB8GA1UdIwQYMBaAFPLj
7vlEwwzgRNM61uRpU41K+kfjMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAAqJNsbtJzPTsN9jzfMW8wqkwCN13cdENdpoRfmm28rTRimOQIF4h6Cn
xG4PkLjVQ0bWeTwmLy1PBUX4zVwQ1d/7hrvrG96cCmcTmOuyxCPL8H6wWlWPOBu1
aOL4ufmQ7kNokW6JEyeV9eKxBrOH1cj0g+dEN3+/cmMfcchmkgzV+lZdwQi2MPTy
/0X8VFCwk+xj8ub24GUYQAfxdG4vVw6c1y5znSDA5v7J36l2Z6jMJTruzUnV0xFz
ZD67YhdblKrtvSXLoUbFfhaUbtNlzj2qqwhnL4PPZQQ1h8TpVt9LlEI0A01nZ1s6
3cnEYOLHpCNUYqELwlE9QTj+BaQAQak=
-----END CERTIFICATE-----
"""
        self.__protocols = {
            'mmbp':'http',
            'mmbps':'https'
        }
        self.ssl_certificate = self._create_ca_file()
        self.__httpxClient_mmbps = httpx.AsyncClient(verify = self.ssl_certificate)
        self.__httpxClient_https = httpx.AsyncClient()

    def _create_ca_file(self):
        temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        temp_cert.write(self.__ca_crt.encode())
        temp_cert.close()
        return temp_cert.name
    
    async def getDNS(self, domain: str) -> str:
        """
        Получение DNS-адреса из сети DNS GW

        :param domain: 
        """
        ip_address, port = await self._resolve_dns(domain)
        result = f"{ip_address}:{port}"
        return result
    
    async def get(self, url: Union[Url, str], data=None, json: Optional[dict] = None, headers=None, stream: bool = False) -> httpx.Response:
        return await self.fetch(url, "GET", data, json, headers, stream)
    async def post(self, url: Union[Url, str], data=None, json: Optional[dict] = None, headers=None, stream: bool = False) -> httpx.Response:
        return await self.fetch(url, "POST", data, json, headers, stream)
    async def put(self, url: Union[Url, str], data=None, json: Optional[dict] = None, headers=None, stream: bool = False) -> httpx.Response:
        return await self.fetch(url, "PUT", data, json, headers, stream)
    async def patch(self, url: Union[Url, str], data=None, json: Optional[dict] = None, headers=None, stream: bool = False) -> httpx.Response:
        return await self.fetch(url, "PATCH", data, json, headers, stream)
    
        
        

    async def fetch(self, url: Union[Url, str], method: str = 'GET', data=None, json: Optional[dict] = None, headers=None, stream: bool = False) -> httpx.Response:
        """
        Асинхронный метод для выполнения запросов к серверам MMBPS и HTTPS.
        """
        if isinstance(url, str):
            url = Url(url)



        if url.scheme in ('mmbps', 'mmbp'):
            response = await self._fetch_mmbps(url, method, data, json, headers, stream)
        elif url.scheme in ('https', 'http'):
            response = await self._fetch_any(url, method, data, json, headers, stream)
        else:
            raise ValueError("Unsupported URL scheme")
        
        return response # type: ignore

    def fetch_sync(self, url: str, method: str = 'GET', data=None, json=None, headers=None, stream: bool = False, verify = False):
        """Синхронный метод для выполнения запросов."""
        with ThreadPoolExecutor() as executor:
            future = executor.submit(self._run_asyncio_task_fetch_sync__, url, method, data, json, headers, stream)
            result = future.result()
        return result

    def _run_asyncio_task_fetch_sync__(self, url, method, data, json, headers, stream):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.fetch(url, method, data, json, headers, stream))
        finally:
            loop.close()
        return result

    async def _fetch_any(self, url: Url, method: str = 'GET', data=None, json=None, headers=None, stream=False, verify = False) -> Union[AsyncIterable[bytes], httpx.Response]:
        if stream:
            return self._fetch_https_stream(url, method, data, json, headers)
        else:
            if url.hostname not in self.__servers:
                return await self._fetch_https(url, method, data, json, headers, verify)
            else:
                return await self._fetch_https_keep_alive(url, method, data, json, headers)

    async def _fetch_https_stream(self, url: Url, method: str = 'GET', data=None, json=None, headers=None) -> AsyncIterable[bytes]:
        """Стриминг HTTPS запроса с использованием httpx."""
        async with httpx.AsyncClient() as client:
            try:
                async with client.stream(method, url.getUrl(), data=data, json = json, headers=headers) as response:
                    logging.debug(f"HTTPS stream response received: {response.status_code}")

                    async for chunk in response.aiter_bytes():
                        yield chunk

            except httpx.TimeoutException:
                logging.debug("HTTPS request timed out")
                raise Exceptions.ServerTimeoutError("Запрос к серверу завершился по тайм-ауту")

            except httpx.ConnectError:
                logging.debug("Failed to connect to server")
                raise Exceptions.ErrorConnection("Не удалось подключиться к серверу")

            except httpx.HTTPStatusError as e:
                logging.debug(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
                raise Exceptions.InvalidServerResponseError(f"Некорректный ответ от сервера: {e.response.status_code}")

            except httpx.RequestError as e:
                logging.debug(f"HTTPS request failed: {e}")
                raise Exceptions.UnexpectedError(f"Неожиданная ошибка запроса HTTPS: {str(e)}")

    async def _get_mmb_verify_crt(self, url: Url) -> Union[bool, str]:
        if url.scheme == 'mmbps':
            return self.ssl_certificate
        else:
            return False
    async def _fetch_https(self, url: Url, method: str = 'GET', data=None, json=None, headers=None, verify=False) -> httpx.Response:
        async with httpx.AsyncClient(verify=verify, follow_redirects=True) as client:
            try:
                response = await client.request(method, url.getUrl(), data=data, json=json, headers=headers)
                return response

            except httpx.TimeoutException:
                logging.debug("HTTPS request timed out")
                raise Exceptions.ServerTimeoutError("Запрос к серверу завершился по тайм-ауту")

            except httpx.ConnectError:
                logging.debug("Failed to connect to server")
                raise Exceptions.ErrorConnection("Не удалось подключиться к серверу")

            except httpx.HTTPStatusError as e:
                logging.debug(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
                raise Exceptions.InvalidServerResponseError(f"Некорректный ответ от сервера: {e.response.status_code}")

            except httpx.RequestError as e:
                logging.debug(f"HTTPS request failed: {e}")
                raise Exceptions.UnexpectedError(f"Неожиданная ошибка запроса HTTPS: {str(e)}")
    async def _fetch_https_keep_alive(self, url: Url, method: str = 'GET', data=None, json=None, headers=None) -> httpx.Response:
        try:
            response = await self.__httpxClient_mmbps.request(method, url.getUrl(), data=data, json=json, headers=headers)
            return response

        except httpx.TimeoutException:
            logging.debug("HTTPS request timed out")
            raise Exceptions.ServerTimeoutError("Запрос к серверу завершился по тайм-ауту")

        except httpx.ConnectError:
            logging.debug("Failed to connect to server")
            raise Exceptions.ErrorConnection("Не удалось подключиться к серверу")

        except httpx.HTTPStatusError as e:
            logging.debug(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
            raise Exceptions.InvalidServerResponseError(f"Некорректный ответ от сервера: {e.response.status_code}")

        except httpx.RequestError as e:
            logging.debug(f"HTTPS request failed: {e}")
            raise Exceptions.UnexpectedError(f"Неожиданная ошибка запроса HTTPS: {str(e)}")

    async def _fetch_mmbps(self, url: Url, method: str = 'GET', data=None, json = None, headers=None, stream: bool = False):

        ip_address, port = await self._resolve_dns(url.hostname)
        verify = await self._get_mmb_verify_crt(url)
        url.hostname = f'{ip_address}:{port}'
        url.scheme = self.__protocols[url.scheme]
        return await self._fetch_any(url, method, data, json, headers, stream, verify = verify) # type: ignore

    async def _resolve_dns(self, hostname: str):
        
        dns_query_url = f"{self.__root_dns_server}/servers?d={hostname}"
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await client.get(dns_query_url)
                if response.status_code == 404:
                    logging.error(f"DNS request failed: {response.status_code} - Server Not Found")
                    raise Exceptions.DNS.DNSServerNotFoundError("DNS server not found")
                elif response.status_code == 403:
                    logging.error(f"DNS request failed: {response.status_code} - Access Denied")
                    raise Exceptions.DNS.DNSAccessDeniedError("Access denied to DNS server")
                elif response.status_code == 500:
                    logging.error(f"DNS request failed: {response.status_code} - Server Failure")
                    raise Exceptions.DNS.DNSServerFailureError("DNS server failure")
                elif response.status_code != 200:
                    logging.error(f"DNS request failed: {response.status_code}")
                    raise Exceptions.DNS.UnexpectedError("Invalid DNS response status")

                result = response.json()
                ip_address = result.get('ip')
                if not ip_address:
                    raise Exceptions.DNS.DNSResponseError("Invalid DNS response format: 'ip' field is missing")

                port = result.get('port', 443)
                return ip_address, port

            except httpx.TimeoutException:
                logging.debug("Connection timeout during DNS resolution")
                raise Exceptions.DNS.DNSTimeoutError("Timeout during DNS resolution")
            except httpx.RequestError as e:
                logging.debug(f"Request error during DNS resolution: {e}")
                raise Exceptions.DNS.ErrorConnection("Connection error during DNS resolution")
            except Exception as e:
                logging.debug(f"Unexpected error during DNS resolution: {e}")
                raise Exceptions.DNS.UnexpectedError("Unexpected error during DNS resolution")


    def addServer(self, server_url: str):
        """Добавить постоянное подключение к серверу."""
        self.__servers[server_url] = True

    def delServer(self, server_url: str):
        """Удалить постоянное подключение к серверу."""
        if server_url in self.__servers:
            del self.__servers[server_url]
            logging.debug(f"Server removed: {server_url}")
    
    def close(self):
        if os.path.exists(self.ssl_certificate):
            os.remove(self.ssl_certificate)
Client = _Client()





