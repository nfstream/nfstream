import hashlib
from nfstream import NFPlugin
from dpkt.ip import IP, IP_PROTO_TCP, IP_PROTO_UDP


# JA4 construction functions
def get_protocol(packet):
    """Protocol detection function, also returns packet payload (TCP or UDP)
        (protocol detection will be used in the future, but for the moment
        it's not necessary, since only TCP fingerprints are generated)
    Args:
        packet (NFPacket): selected packet

    Returns:
        protocol (str): detected protocol, "t" for TCP, "q" for QUIC
        payload (scapy.layers.inet.TCP or scapy.layers.inet.UDP): payload of the packet (at transport layer level)
    """
    # If the packet is not IPv4, None is returned
    # (only IPv4 packets are considered for JA4 fingerprint extraction)
    if packet.ip_version != 4:
        return None, None
    # TCP detection and TCP payload extraction
    ip_packet = IP(packet.ip_packet)
    if ip_packet.p == IP_PROTO_TCP:
        # TCP load is returned
        return ("t", ip_packet.tcp.data)
    # QUIC detection and QUIC payload extraction
    elif ip_packet.p == IP_PROTO_UDP:
        udp_packet = ip_packet.udp
        if udp_packet.dport == 443 or udp_packet.dport == 80:
            # QUIC load is returned
            return ("t", udp_packet.data)
    else:
        return None, None


def make_entry(tls_dict, split_payload, entry_len):
    """TLS dictionary construction helper function

    Args:
        tls_dict (dict): dictionary in construction (for relative entry lengths)
        split_payload (list): list of payload bytes
        entry_len (int or str): specified length of desired entry

    Returns:
        entry (list): computed dictionary entry (TLS field) as list of bytes
        split_payload (list): updated list of payload bytes (without the entry)
    """
    if isinstance(entry_len, str):
        if tls_dict[entry_len]:
            entry_len = int("".join(tls_dict[entry_len]), 16)
        else:
            entry_len = 0
    if entry_len == 0:
        return None, split_payload
    else:
        entry = split_payload[:entry_len]
        del split_payload[:entry_len]
        return entry, split_payload


# TLS dict header lengths
headers_len_dict = {
    "record_header": 5,
    "handshake_header": 4,
    "tls_version": 2,
}

# TLS dict field lengths for each type of hello
tls_len_dict = {
    # Client hello
    "01": {
        "random": 32,
        "session_id_len": 1,
        "session_id": "session_id_len",
        "cypher_suites_len": 2,
        "cypher_suites": "cypher_suites_len",
        "compression_methods_len": 1,
        "compression_methods": "compression_methods_len",
        "extensions_len": 2,
        "extensions": "extensions_len",
    },
    # Server hello
    "02": {
        "random": 32,
        "session_id_len": 1,
        "session_id": "session_id_len",
        "cypher_suite": 2,
        "compression_method": 1,
        "extensions_len": 2,
        "extensions": "extensions_len",
    },
}


def make_headers_dict(transport_payload):
    """TLS headers dictionary construction function

    Args:
        transport_payload (str): transport layer payload (TCP or UDP), string of hexadecimal bytes

    Returns:
        headers_dict (dict): dictionary with the TLS headers of the packet
        split_payload (list): list of payload bytes (without the headers)
    """
    # Payload is converted to lowercase to avoid problems
    transport_payload = transport_payload.lower()
    # Payload is split into pairs of characters (bytes)
    split_payload = [
        transport_payload[i : i + 2] for i in range(0, len(transport_payload), 2)
    ]
    headers_dict = {}
    # Dictionary is constructed using specified lengths
    for entry_name, entry_len in headers_len_dict.items():
        headers_dict[entry_name], split_payload = make_entry(
            headers_dict, split_payload, entry_len
        )
    return headers_dict, split_payload


# TLS dictionary construction function
def make_tls_dict(split_payload, hello_type):
    """TLS dictionary construction function

    Args:
        split_payload (list): list of packet payload bytes (without the headers)

    Returns:
        tls_dict: dictionary with the TLS fields
    """
    tls_dict = {}
    # Dictionary is constructed using specified lengths
    for entry_name, entry_len in tls_len_dict[hello_type].items():
        tls_dict[entry_name], split_payload = make_entry(
            tls_dict, split_payload, entry_len
        )
    return tls_dict


# Client/Server Hello assertion function
def check_cs_hello(headers_dict):
    """Client/Server Hello assertion function

    Args:
        headers_dict (dict): dictionary of packet TLS headers

    Returns:
        hello_type (str): detected type of hello ("01" for CLIENT HELLO, "02" for SERVER HELLO)
    """
    # Checks that record header starts by 16 03
    # 16: handshake code
    # 03: TLS protocol (SSL 3.X)
    assert headers_dict["record_header"][:2] == ["16", "03"]
    # Checks that handshake header starts by 01 or 02
    # 01: CLIENT HELLO code
    # 02: SERVER HELLO code
    hello_type = headers_dict["handshake_header"][0]
    assert (hello_type == "01") or (hello_type == "02")
    # Checks that TLS version starts by 03
    # 03: TLS protocol is disguised as SSL 3.X
    # Checks that TLS version ends by 01, 02, 03 or 04 (TLS 1.0, 1.1, 1.2 or 1.3)
    assert headers_dict["tls_version"][0] == "03"
    assert headers_dict["tls_version"][0] in ["01", "02", "03", "04"]
    # Returns detected hello type
    return hello_type


def make_cipher_list(tls_dict):
    """Makes list of cipher suites

    Args:
        tls_dict (dict): Dictionary of TLS fields

    Returns:
        cipher_list (list): List of cipher suites
    """
    cipher_payload = tls_dict["cypher_suites"]
    cipher_list = []
    # Iterates over the full lenght of the cipher field
    while len(cipher_payload) > 0:
        # Gets cipher suite code
        cipher = cipher_payload[:2]
        # Deletes taken code from the payload
        del cipher_payload[:2]
        cipher_list.append("".join(cipher))
    return cipher_list


def make_extensions_dict(tls_dict):
    """Makes list of extensions based on specified extension length

    Args:
        tls_dict (dict): Dictionary of TLS fields

    Returns:
        extensions_dict (dict): Dictionary of TLS extensions
    """
    extensions_payload = tls_dict["extensions"]
    extensions_dict = {}
    if not extensions_payload:
        return extensions_dict
    while len(extensions_payload) > 0:
        extension_type = extensions_payload[:2]
        del extensions_payload[:2]
        extension_len = extensions_payload[:2]
        del extensions_payload[:2]
        if extension_len == ["00", "00"]:
            extension_data = None
        else:
            extension_data = extensions_payload[: int("".join(extension_len), 16)]
            del extensions_payload[: int("".join(extension_len), 16)]
        extensions_dict["".join(extension_type)] = extension_data
    return extensions_dict


def make_supported_list(extensions_dict):
    """Makes list of supported versions from supported versions extension

    Args:
        extensions_dict (dict): Dictionary of TLS extensions

    Returns:
        supported_list (list): List of supported TLS versions
    """
    supported_payload = extensions_dict["002b"]
    supported_len = supported_payload[:1]
    del supported_payload[:1]
    assert len(supported_payload) == int("".join(supported_len), 16)
    supported_list = []
    while len(supported_payload) > 0:
        signature_algorithm = supported_payload[:2]
        del supported_payload[:2]
        supported_list.append("".join(signature_algorithm))
    return supported_list


def get_tls_version(extensions_dict, tls_dict, hello_type):
    """Gets latest supported TLS version from supported versions extension

    Args:
        extensions_dict (dict): Dictionary of TLS extensions
        tls_dict (dict): Dictionary of TLS fields
        hello_type (str): Type of hello ("01" for CLIENT HELLO, "02" for SERVER HELLO)

    Returns:
        latest_version (str): Latest supported version
    """
    # If 002b extension is present (supported versions), get the TLS version from it
    if "002b" in extensions_dict.keys():
        # If CLIENT HELLO, the highest supported TLS version is returned
        if hello_type == "01":
            # Supported TLS version list is created and removed of GREASE elements
            supported_list = remove_grease(make_supported_list(extensions_dict))
            # Latest TLS version is selected
            supported_list.sort(key=lambda h: int(h, 16))
            tls_version = supported_list[-1]
        # If SERVER HELLO, chosen TLS version is returned
        elif hello_type == "02":
            tls_version = "".join(extensions_dict["002b"])
    # If extension 002b is not present, specified TLS version in TLS header is returned
    # NB: don't mistake with the TLS version in the record header, which is always 0301 (SSL 3.1)
    else:
        tls_version = "".join(tls_dict["tls_version"])
    # First two bytes are translated to decimal (version number)
    # First byte is substracted 2 units and second byte is substracted 1 unit, because TLS 1.0 is disguised as SSL 3.1
    first_version_digit = str(int(tls_version[:2], 16) - 2)
    second_version_digit = str(int(tls_version[2:], 16) - 1)
    return first_version_digit + second_version_digit


def get_sni(extensions_dict):
    """Gets SNI from SNI extension

    Args:
        extensions_dict (dict): Dictionary of TLS extensions

    Returns:
        sni (str): Server Name Indication, "d" for domain, "i" for IP
    """
    # If 0000 extension is present (SNI) "d" is returned, else "i"
    if "0000" in extensions_dict.keys():
        return "d"
    else:
        return "i"


def is_grease(candidate_str):
    """Checkis if a

    Args:
        candidate_str (str): candidate string

    Returns:
        is_grease (bool): whether the string is GREASE or not
    """
    # Asserts that both le length and the type of the string are correct
    assert len(candidate_str) == 4
    assert isinstance(candidate_str, str)
    # Checks for GREASE pattern
    if candidate_str[0] == candidate_str[2] and candidate_str[1] == candidate_str[3]:
        if candidate_str[1] == "a" or candidate_str[1] == "A":
            return True
    return False


def get_nongrease_num(iterable):
    """Counts how many elements of an iterable are not GREASE, truncated to a
        maximum of 99 (JA4 specification)

    Args:
        iterable (dict or list): iterable element

    Returns:
        n_grease (int): number of non-GREASE elements
    """
    num = 0
    if isinstance(iterable, list):
        iter = iterable
    elif isinstance(iterable, dict):
        iter = iterable.keys()
    for element in iter:
        # If not GREASE, add 1 to the counter
        if not is_grease(element):
            num += 1
        # Stop counting if the counter reaches 99
        if num == 99:
            break
    return f"{num:02}"


def remove_grease(remove_list):
    """Removes GREASE elements from a list

    Args:
        remove_list (list): list to have its GREASE elements removed

    Returns:
        remove_list (list): updated list without GREASE elements
    """
    for index, element in enumerate(remove_list):
        if is_grease(element):
            del remove_list[index]
    return remove_list


def make_alpn_list(extensions_dict):
    """Makes the list of supported ALPN protocols from the ALPN extension

    Args:
        extensions_dict (dict): Dictionary of TLS extensions

    Returns:
        alpn_list (list): List of supported ALPN protocols
    """
    # ALPN extension (code 0010) is extracted from the extensions dictionary
    alpn_payload = extensions_dict["0010"]
    # ALPN extension length is extracted and deleted from the payload
    alpn_len = alpn_payload[:2]
    del alpn_payload[:2]
    # Checks that the length of the ALPN extension agrees with the specified length
    assert len(alpn_payload) == int("".join(alpn_len), 16)
    alpn_list = []
    # Iterates over the full lenght of the ALPN extension
    while len(alpn_payload) > 0:
        # Grab protocol string length
        protocol_len = alpn_payload[:1]
        # Delete protocol string length from the payload
        del alpn_payload[:1]
        # Grab protocol string, using the length obtained in the previous step (converted to decimal)
        protocol_string = "".join(alpn_payload[: int("".join(protocol_len), 16)])
        # Delete protocol string from the payload
        del alpn_payload[: int("".join(protocol_len), 16)]
        alpn_list.append(protocol_string)
    return alpn_list


def make_signaturealgs_list(extensions_dict):
    """Makes the list of supported signature algorithms from the signature algorithms extension

    Args:
        extensions_dict (dict): Dictionary of TLS extensions

    Returns:
        signaturealgs_list (list): List of supported signature algorithms
    """
    if "000d" not in extensions_dict.keys():
        return []
    # Signature algorithms extension (code 000d) is extracted from the extensions dictionary
    signaturealgs_payload = extensions_dict["000d"]
    # Signature algorithms extension length is extracted and deleted from the payload
    signaturealgs_len = signaturealgs_payload[:2]
    del signaturealgs_payload[:2]
    # Checks that the length of the ALPN extension agrees with the specified length
    assert len(signaturealgs_payload) == int("".join(signaturealgs_len), 16)
    signaturealgs_list = []
    # Iterates over the full lenght of the signature algorithms extension
    while len(signaturealgs_payload) > 0:
        # Grab signature algorithm
        signature_algorithm = signaturealgs_payload[:2]
        # Delete signature algorithm from the payload
        del signaturealgs_payload[:2]
        # Add signature algorithm to the list
        signaturealgs_list.append("".join(signature_algorithm))
    return signaturealgs_list


def get_alpn_value(extensions_dict):
    """Gets the first and last character of the first ALPN protocol from the ALPN extension (if present)

    Args:
        extensions_dict (dict): Dictionary of TLS extensions

    Returns:
        alpn_str (str): First and last character of the first ALPN protocol
    """
    # If ALPN extension is present
    if "0010" in extensions_dict.keys():
        # ALPN list is created
        alpn_list = make_alpn_list(extensions_dict)
        # Checks that the ALPN list is not empty
        if len(alpn_list) > 0:
            # First ALPN protocol is extracted and decoded
            first_alpn = bytearray.fromhex(alpn_list[0]).decode("utf-8")
            # Return first and last character of the first ALPN protocol
            return first_alpn[0] + first_alpn[-1]
    # If the ALPN protocol extension is empty, "00" is returned (JA4 specification)
    return "00"


def make_ja4_a(protocol, tls_dict, hello_type):
    """Makes part A of the JA4/S signature

    Args:
        protocol (str): Protocol character ("t" for TCP, "q" for QUIC)
        tls_dict (dict): Dictionary of TLS fields
        hello_type (str): Type of hello ("01" for CLIENT HELLO, "02" for SERVER HELLO)

    Returns:
        ja4_a_string: Part A of the JA4/S signature
        cipher_list (list): List of cipher suites
        extensions_dict (dict): Dictionary of TLS extensions
    """
    # Initializes the JA4 string with the protocol character
    ja4_a_string = protocol
    # Constructs the extensions dictionary
    extensions_dict = make_extensions_dict(tls_dict)
    # Adds the TLS version to the JA4 string
    ja4_a_string += get_tls_version(extensions_dict, tls_dict, hello_type)
    # Adds CLIENT HELLO fields to the JA4 string
    if hello_type == "01":
        # Adds the SNI to the JA4 string
        ja4_a_string += get_sni(extensions_dict)
        # Constructs the list of cipher suites
        cipher_list = make_cipher_list(tls_dict)
        # Adds the number of (non GREASE) cipher suites to the JA4 string
        ja4_a_string += get_nongrease_num(cipher_list)
    # If SERVER HELLO, the chosen cipher suite is added to the JA4 string
    else:
        cipher_list = tls_dict["cypher_suite"]
    # Adds the number of (non GREASE) extensions to the JA4 string
    ja4_a_string += get_nongrease_num(extensions_dict)
    # Adds the first and last character of the first ALPN protocol to the JA4 string
    ja4_a_string += get_alpn_value(extensions_dict)
    return ja4_a_string, cipher_list, extensions_dict


def make_ja4_b(cipher_list, hello_type):
    """Makes part B of the JA4/S signature

    Args:
        cipher_list (list): List of cipher suites
        hello_type (str): Type of hello ("01" for CLIENT HELLO, "02" for SERVER HELLO)

    Returns:
        ja4_b_string: Part B of the JA4/S signature
    """
    # If SERVER HELLO, the unhashed code of the chosen cipher suite is returned
    if hello_type == "02":
        return "".join(cipher_list)
    # If CLIENT HELLO, the hashed code of the chosen cipher suite is returned
    # Start by removing GREASE elements from the cipher list
    cipher_list = remove_grease(cipher_list)
    # Cipher list is sorted by its hexadecimal value
    cipher_list.sort(key=lambda h: int(h, 16))
    # Cipher list is converted to a string separated by commas
    cipher_str = ",".join(cipher_list).encode()
    # Cipher list is hashed (SHA-256) and truncated to 12 hexadecimal characters
    if len(cipher_str) > 0:
        return hashlib.sha256(cipher_str).hexdigest()[:12]
    # If there are no ciphers, an unhashed string of 12 zeros is returned (JA4 specification)
    else:
        return "0" * 12


def make_ja4_c(extensions_dict, hello_type):
    """Makes part C of the JA4/S signature

    Args:
        extensions_dict (dict): Dictionary of TLS extensions
        hello_type (str): Type of hello ("01" for CLIENT HELLO, "02" for SERVER HELLO)

    Returns:
        ja4_c_string: Part C of the JA4/S signature
    """
    # List of extension codes is created
    extensions_list = list(extensions_dict.keys())
    # If CLIENT HELLO, the list of extensions is sorted and GREASE elements are removed from it (JA4 specification)
    if hello_type == "01":
        # Remove GREASE elements from the list of extensions
        extensions_list = remove_grease(extensions_list)
        # Remove SNI and ALPN from the list of extensions (already considered in part A)
        if "0000" in extensions_dict.keys():
            extensions_list.remove("0000")
        if "0010" in extensions_dict.keys():
            extensions_list.remove("0010")
        # Sort the list of extensions by its hexadecimal value
        extensions_list.sort(key=lambda h: int(h, 16))
    # Extensions list is converted to a string separated by commas
    extensions_str = ",".join(extensions_list)
    # If CLIENT HELLO, the list of signature algorithms must be added to the JA4 string
    if hello_type == "01":
        # List of signature algorithms is created
        signaturealgs_list = make_signaturealgs_list(extensions_dict)
        # If there are signature algorithms, they are added to the JA4 string
        if len(signaturealgs_list) > 0:
            # Remove GREASE elements from the list of signature algorithms
            signaturealgs_list = remove_grease(signaturealgs_list)
            # Join the list of signature algorithms into a string separated by commas
            signaturealgs_str = ",".join(signaturealgs_list)
            # Join the list of extensions and the list of signature algorithms into a string separated by an underscore
            extensions_str += "_" + signaturealgs_str
    # Extensions string is encoded to bytes
    extensions_str = extensions_str.encode()
    # Extensions string is hashed (SHA-256) and truncated to 12 hexadecimal characters
    if len(extensions_str) > 0:
        return hashlib.sha256(extensions_str).hexdigest()[:12]
    # If there are no extensions nor algorithms, an unhashed string of 12 zeros is returned (JA4 specification)
    else:
        return "0" * 12


def get_ja4(packet, pred_hello_type):
    # Detect if the packet protocol is TLS or QUIC and get the payload
    protocol, raw_payload = get_protocol(packet)
    if (not raw_payload) and protocol is None:
        return None, None
    else:
        hex_payload = bytes(raw_payload).hex()
    # Construct the dictionary with the headers of the packet
    headers_dict, split_payload = make_headers_dict(hex_payload)
    try:
        # Check that the selected packet is a TLS HELLO (CLIENT or SERVER)
        hello_type = check_cs_hello(headers_dict)
        # Check that the selected packet is of the specified type when calling the function
        assert hello_type == pred_hello_type
    except AssertionError:
        # If the selected packet is not a TLS HELLO, None is returned
        return None, None
    # TLS dictionary is constructed with the TLS fields and updated with the headers fields
    tls_dict = make_tls_dict(split_payload, pred_hello_type)
    tls_dict.update(headers_dict)
    # First part of the signature is obtained
    ja4_a, cipher_list, extensions_dict = make_ja4_a(protocol, tls_dict, hello_type)
    # Second part of the signature is obtained
    ja4_b = make_ja4_b(cipher_list, hello_type)
    # Third part of the signature is obtained
    ja4_c = make_ja4_c(extensions_dict, hello_type)
    # Join the three JA4 signature parts
    ja4 = (ja4_a + "_" + ja4_b + "_" + ja4_c).lower()
    packet_id = "".join(tls_dict["random"])
    return ja4, packet_id


class JA4(NFPlugin):
    """NFPlugin extension for additional flow statistics

    Args:
        NFPlugin (nfs.NFPlugin): main class for extending NFStream
    """

    def __init__(self, throw_warns=True):
        super().__init__()
        self.throw_warns = throw_warns

    def on_init(self, packet, flow):
        """Initializes flow statistics

        Args:
            packet (nfs.NFPacket): Network Flow Packet
            flow (nfs.NFlow): Flow representation within NFStream
        """
        # Flow starting time
        flow.udps._start_time = packet.time

        # Flow JA4
        flow.udps.ja4 = None
        flow.udps.ja4s = None
        flow.udps._client_random = None
        flow.udps._server_random = None
        flow.udps._ja4_eligible = False
        if packet.syn and not packet.ack:
            flow.udps._ja4_eligible = True

        # TCP handshake
        flow.udps.tcp_syn_flag = False
        flow.udps.tcp_syn_synack_flag = False
        flow.udps.tcp_synack_ack_flag = False

        # Checking if first packet is a SYN packet
        if packet.syn and not packet.ack:  # SYN packet
            flow.udps.tcp_syn_flag = True

    def on_update(self, packet, flow):
        """Updates flow statistics with its belonging set of packets.

        Args:
            packet (nfs.NFPacket): Network Flow Packet
            flow (nfs.NFlow): Flow representation within NFStream
        """

        # Checks if the flow is eligible for JA4 signature generation
        if flow.udps._ja4_eligible:
            # Generate client JA4 signature if it doesn't have one
            if not flow.udps.ja4:
                try:
                    flow.udps.ja4, flow.udps._client_random = get_ja4(packet, "01")
                except Exception:
                    flow.udps.ja4, flow.udps._client_random = None, None
            # If there exists a client JA4 signature and the packet flows in the opposite direction, generate server JA4 signature
            elif flow.udps.ja4:
                try:
                    flow.udps.ja4s, flow.udps._server_random = get_ja4(packet, "02")
                except Exception:
                    flow.udps.ja4, flow.udps._client_random = None, None
                if flow.udps.ja4s:
                    flow.udps._ja4_eligible = False

        if (
            flow.udps.tcp_synack_ack_flag
            and flow.udps._ja4_eligible
            and not flow.udps.ja4
        ):
            flow.udps._ja4_eligible = False

        # TCP handshake
        if flow.udps._ja4_eligible:
            if not flow.udps.tcp_syn_flag:
                if packet.syn and not packet.ack:  # SYN packet
                    flow.udps.tcp_syn_flag = True
            elif not flow.udps.tcp_syn_synack_flag:
                if packet.syn and packet.ack:  # SYN+ACK packet
                    flow.udps.tcp_syn_synack_flag = True
            elif not flow.udps.tcp_synack_ack_flag:
                if packet.ack and not packet.syn:  # ACK packet
                    flow.udps.tcp_synack_ack_flag = True

    def on_expire(self, flow):
        # Dropping temporal udps
        del flow.udps._start_time
        del flow.udps._client_random
        del flow.udps._server_random
        del flow.udps._ja4_eligible
        del flow.udps.tcp_syn_flag
        del flow.udps.tcp_syn_synack_flag
        del flow.udps.tcp_synack_ack_flag
