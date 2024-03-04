import logging
import uuid

from rich.console import Console
from tornado import gen

from pynostr.event import EventKind
from pynostr.filters import Filters, FiltersList
from pynostr.message_type import RelayMessageType
from pynostr.relay_list import RelayList
from pynostr.relay_manager import RelayManager
from pynostr.utils import get_public_key, get_relay_list, get_timestamp

log = logging.getLogger(__name__)


@gen.coroutine
def print_message(message_json, url):
    message_type = message_json[0]
    if message_type == RelayMessageType.EVENT:
        print(f"{url}: {str(message_json)}")


if __name__ == "__main__":

    console = Console()

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    ch = logging.StreamHandler()
    ch.setLevel(4)
    ch.setFormatter(formatter)
    log.addHandler(ch)

    # identity_str = input("Obtenha seguidores para identidade (npub or nip05): ")
    identity_str = "npub1g94kghlmds4j3329ve3vv773tnyl8nr89fqta30jwntcym2sty0sf4l9sp"
    identity = get_public_key(identity_str)

    if identity != "":
        print(f"identidade está definida como {identity.bech32()}")
    else:
        raise Exception("identidade não válida")

    relay_list = RelayList()
    relay_list.append_url_list(get_relay_list())

    print(f"Verificando {len(relay_list.data)} relays...")

    relay_list.update_relay_information(timeout=0.5)
    relay_list.drop_empty_metadata()

    print(f"Encontrado {len(relay_list.data)} relays...")

    # O tempo limite deve ser definido como 0 e close_on_eose deve ser definido como falso
    # Quando message_callback_url é definido como True, a função message_callback
    # deve processar também o URL
    relay_manager = RelayManager(error_threshold=3, timeout=0)
    relay_manager.add_relay_list(
        relay_list,
        close_on_eose=False,
        message_callback=print_message,
        message_callback_url=True,
    )

    start_time = get_timestamp()

    filters = FiltersList(
        [  # insira a condição do filtro
            Filters(
                since=start_time,
                kinds=[EventKind.TEXT_NOTE],
                pubkey_refs=[
                    identity.hex(),
                ],
            )
        ]
    )
    subscription_id = uuid.uuid1().hex
    relay_manager.add_subscription_on_all_relays(subscription_id, filters)
    relay_manager.run_sync()