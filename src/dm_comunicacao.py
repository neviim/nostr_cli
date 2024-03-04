#!/usr/bin/env python

import getpass
import uuid

import tornado.ioloop
from rich.console import Console
from tornado import gen

from pynostr.base_relay import RelayPolicy
from pynostr.encrypted_dm import EncryptedDirectMessage
from pynostr.event import Event, EventKind
from pynostr.filters import Filters, FiltersList
from pynostr.key import PrivateKey
from pynostr.message_pool import MessagePool
from pynostr.message_type import RelayMessageType
from pynostr.relay import Relay
from pynostr.utils import get_public_key, get_timestamp

import secret

@gen.coroutine
def print_dm(message_json):
    message_type = message_json[0]
    if message_type == RelayMessageType.EVENT:
        event = Event.from_dict(message_json[2])
        if event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
            if event.has_pubkey_ref(sender_pk.public_key.hex()):
                rdm = EncryptedDirectMessage.from_event(event)
                rdm.decrypt(sender_pk.hex(), public_key_hex=recipient.hex())
                print(f"Novo DM recebido: {event.date_time()}> {rdm.cleartext_content}")
    elif message_type == RelayMessageType.OK:
        print(message_json)
    elif message_type == RelayMessageType.NOTICE:
        print(message_json)


if __name__ == "__main__":

    console = Console()

    # pk = getpass.getpass(prompt="Insira a chave privada do remetente (nova quando vazia): ")
    pk = secret.private_key
    if len(pk) == 0:
        sender_pk = PrivateKey()
    else:
        sender_pk = PrivateKey.from_nsec(pk)

    print(f"Novos DM são enviados de Qubit.: {sender_pk.public_key.bech32()}")

    # recipient_str = input("destinatário (npub or nip05): ")
    recipient_str = "npub1g94kghlmds4j3329ve3vv773tnyl8nr89fqta30jwntcym2sty0sf4l9sp"
    recipient = get_public_key(recipient_str)
    if recipient != "":
        print(f"destinatário está definido para: {recipient.bech32()}")
    else:
        raise Exception("destinatário não é válido")
    relay_url = input("relay (wss://...): ")
    relay_url = "wss://"+relay_url
    dm = EncryptedDirectMessage()
    dm.encrypt(
        sender_pk.hex(),
        cleartext_content="Qubit: Olá, responda a este dm para teste :).",
        recipient_pubkey=recipient.hex(),
    )

    filters = FiltersList(
        [
            Filters(
                authors=[recipient.hex()],
                kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE],
                since=get_timestamp(),
                limit=10,
            )
        ]
    )

    subscription_id = uuid.uuid1().hex
    io_loop = tornado.ioloop.IOLoop.current()
    message_pool = MessagePool(first_response_only=False)
    policy = RelayPolicy()
    r = Relay(
        relay_url,
        message_pool,
        io_loop,
        policy,
        timeout=5,
        close_on_eose=False,
        message_callback=print_dm,
    )
    dm_event = dm.to_event()
    dm_event.sign(sender_pk.hex())
    r.publish(dm_event.to_message())
    r.add_subscription(subscription_id, filters)

    try:
        io_loop.run_sync(r.connect)
    except gen.Return:
        pass
    io_loop.stop()