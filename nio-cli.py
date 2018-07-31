#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import unicode_literals

import socket
import ssl
import time

import click
import logbook
import socks
from logbook import Logger, StderrHandler

import nio
from nio.client import HttpClient, TransportType
from nio.responses import ErrorResponse, LoginResponse

click.disable_unicode_literals_warning = True


class CliClient(object):
    def __init__(
        self,
        user,
        password,
        host=None,
        port=None,
        ssl_insecure=False,
        proxy=None,
        proxy_port=None,
        proxy_type=None
    ):
        self.host = host or "matrix.org"
        self.port = port or 443
        self.user = user
        self.password = password
        self.ssl_insecure = ssl_insecure

        self.proxy = proxy or None
        self.proxy_port = proxy_port or None
        self.proxy_type = proxy_type or None

        self.logger = Logger("matrix-cli")


def validate_host(ctx, param, value):
    if not value:
        return None, None

    if (param.name) == "host":
        default_port = 443
    else:
        default_port = None

    try:
        host, _, port = value.partition(":")
        return (host, int(port) if port else default_port)
    except ValueError:
        raise click.BadParameter("hosts need to be in format host:[port]")


def validate_proxy_type(ctx, param, value):
    if value == "http":
        return socks.PROXY_TYPE_HTTP
    elif value == "socks4":
        return socks.PROXY_TYPE_SOCKS4
    elif value == "socks5":
        return socks.PROXY_TYPE_SOCKS5
    else:
        raise ValueError


@click.group()
@click.argument("host", callback=validate_host)
@click.argument("user")
@click.argument("password")
@click.option("--verbosity", type=click.Choice([
    "error",
    "warning",
    "info",
    "debug"
]),
              default="error")
@click.option("-k", "--ssl-insecure/--no-ssl-insecure", default=False)
@click.option("--proxy-host", callback=validate_host)
@click.option("--proxy-type", type=click.Choice(["http", "socks4", "socks5"]),
              default="http", callback=validate_proxy_type)
@click.pass_context
def cli(
    ctx,
    host,
    user,
    password,
    verbosity,
    ssl_insecure,
    proxy_host,
    proxy_type
):
    StderrHandler(level=verbosity.upper()).push_application()

    if verbosity == "info":
        nio.logger_group.level = logbook.INFO
    elif verbosity == "warning":
        nio.logger_group.level = logbook.WARNING
    elif verbosity == "error":
        nio.logger_group.level = logbook.ERROR
    elif verbosity == "debug":
        nio.logger_group.level = logbook.DEBUG

    ctx.obj = CliClient(
        user,
        password,
        host[0],
        host[1],
        ssl_insecure,
        proxy_host[0],
        proxy_host[1],
        proxy_type
    )


@cli.command()
@click.pass_obj
@click.option('--loop/--no-loop', default=False)
def sync(cli, loop):
    def sync_func():
        _, data = client.sync()
        sock.sendall(data)
        response = None

        while not response:
            data = client.data_to_send()

            if data:
                sock.sendall(data)

            received_data = sock.recv(4096)
            client.receive(received_data)
            response = client.next_response()

        click.echo(response)

    sock, client = connect(cli)

    _, data = client.login(cli.password)
    sock.sendall(data)

    response = None

    while not response:
        data = client.data_to_send()

        if data:
            sock.sendall(data)

        received_data = sock.recv(4096)
        client.receive(received_data)
        response = client.next_response()

    if not loop:
        sync_func()
        disconnect(sock, client)
        return True

    while True:
        sync_func()
        time.sleep(3)

    disconnect(sock, client)
    return True


@cli.command()
@click.pass_obj
def login(cli):
    sock, client = connect(cli)

    _, data = client.login(cli.password)
    sock.sendall(data)

    response = None

    while not response:
        received_data = sock.recv(4096)
        client.receive(received_data)
        response = client.next_response()

    if isinstance(response, LoginResponse):
        click.echo(response, err=True)
        click.echo(response.access_token)
    elif isinstance(response, ErrorResponse):
        click.echo(str(response))

    disconnect(sock, client)

    return True


def main():
    cli()


def disconnect(sock, client):
    data = client.disconnect()
    sock.sendall(data)

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


def connect(cli):
    context = ssl.create_default_context()

    if cli.ssl_insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        context.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    sock = socks.socksocket()

    if cli.proxy:
        sock.set_proxy(cli.proxy_type, cli.proxy, cli.proxy_port)

    try:
        sock.connect((cli.host, cli.port))
    except socket.error as e:
        raise SystemExit(e)

    try:
        ssl_socket = context.wrap_socket(sock, server_hostname=cli.host)
    except (ssl.SSLError, socket.error) as e:
        raise SystemExit(e)

    negotiated_protocol = ssl_socket.selected_alpn_protocol()
    if negotiated_protocol is None:
        negotiated_protocol = ssl_socket.selected_npn_protocol()

    transport_type = None

    if negotiated_protocol == "http/1.1":
        transport_type = TransportType.HTTP
    elif negotiated_protocol == "h2":
        transport_type = TransportType.HTTP2
    else:
        raise NotImplementedError

    client = HttpClient(cli.host, cli.user)
    data = client.connect(transport_type)

    try:
        ssl_socket.sendall(data)
    except socket.error as e:
        raise SystemExit(e)

    return ssl_socket, client


if __name__ == "__main__":
    main()
