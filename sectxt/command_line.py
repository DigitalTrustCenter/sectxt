"""Module that provides a command-line interface to SecTXT."""

import argparse
from typing import List
from urllib.parse import urlparse

from . import ErrorDict, SecurityTXT, __version__


class TaggedErrorDict(ErrorDict):
    tag: str


def valid_url(url: str) -> bool:
    """Basic URL validator that checks for the presence of a scheme and a network location."""
    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except AttributeError:
        return False


def tag_messages(
    messages_list: List[ErrorDict], message_type: str
) -> List[TaggedErrorDict]:
    """Add message_type to each message in the list as {"tag": message_type}"""

    return [dict(msg, **{"tag": message_type}) for msg in messages_list]


def human_readable_print(messages_list: List[TaggedErrorDict]) -> None:
    """Print messages in a human-readable format"""

    for message in messages_list:
        if message["line"]:
            print(
                "[" + message["tag"] + "]",
                "L" + str(message["line"]) + ":",
                message["code"],
                ":",
                message["message"],
            )
        else:
            print("[" + message["tag"] + "]", message["code"], ":", message["message"])

    if len(messages_list) == 0:
        print("✓ No issues were detected!")


def main() -> int:
    """Main function which parses the arguments, calls SecurityTXT()
    and prints output messages.

    Returns:
        0 if the security.txt file does not contain any errors; otherwise, 1

    """

    parser = argparse.ArgumentParser(description="Parse and validate security.txt")
    parser.add_argument("address", help="website URL or path to local file to check")
    parser.add_argument(
        "--json", action="store_true", help="output the results in JSON format"
    )
    parser.add_argument(
        "--no-recommend-unknown-fields",
        action="store_true",
        help="do not issue notifications for unknown fields",
    )
    parser.add_argument(
        "--show-notifications", action="store_true", help="show notifications"
    )
    parser.add_argument(
        "--show-recommendations", action="store_true", help="show recommendations"
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__
    )
    args = parser.parse_args()

    address_is_local = not valid_url(args.address)

    s = SecurityTXT(
        args.address,
        recommend_unknown_fields=not args.no_recommend_unknown_fields,
        is_local=address_is_local,
    )

    output_messages = tag_messages(s.errors, "ERROR")

    if args.show_recommendations:
        output_messages += tag_messages(s.recommendations, "REC")

    if args.show_notifications:
        output_messages += tag_messages(s.notifications, "NOTE")

    if args.json:
        print(output_messages)
    else:
        human_readable_print(output_messages)

    return 0 if s.is_valid() else 1
