"""The parts of nodo's gateway protocol that node_controller does not speak.

node_controller (celaut-service-libraries) carries a copy of celaut.proto from an
older nodo. It has no StartReference (#578), no GetBalanceStatement (#570) and no
block skip on the request side (#371), and the newer benchmarks need all three. This
module talks to the same gateway with the messages of the nodo that the benchmarks
test.

The messages come from ``nodo_protos/celaut.binpb``, a copy of nodo's own
``protos/celaut_doc.binpb`` (a FileDescriptorSet). It is loaded into a private
descriptor pool, never into the default one: node_controller's ``celaut_pb2`` already
registered a ``celaut.proto`` there, and a second file with that name and other
content cannot be added. Two pools give two sets of classes with the same wire
format, and a call uses the classes of one pool from end to end.

Every gateway RPC has the same gRPC signature (a stream of bee-rpc Buffers each way),
so the calls here use a generic stream-stream method and the index tables of nodo's
``protos/gateway_bee.py`` (GATEWAY_RPCS). A local instance is exempt from the Client
of the RPCs that ask for one, so this module never sends a Client.

The statement checks (``verify_statement``) follow nodo's own reader:
``src/manager/statement_check.py::verify_chain``, ``src/database/ledger.py`` for the
hashes and ``src/manager/balance_statement.py`` for the digest that is signed.
"""
import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
DESCRIPTOR_SET = os.path.join(HERE, "nodo_protos", "celaut.binpb")
GATEWAY_SERVICE = "/celaut.Gateway/"

_pool_lock = threading.Lock()
_MESSAGES = None


def messages():
    """The message classes of nodo's celaut.proto, from a private descriptor pool.

    Loaded on first use, so that importing this module needs neither protobuf nor
    bee-rpc (the unit tests stub both).
    """
    global _MESSAGES
    with _pool_lock:
        if _MESSAGES is not None:
            return _MESSAGES
        from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
        from bee_rpc import buffer_pb2

        files = descriptor_pb2.FileDescriptorSet()
        with open(DESCRIPTOR_SET, "rb") as fh:
            files.ParseFromString(fh.read())
        pool = descriptor_pool.DescriptorPool()
        # celaut.proto imports buffer.proto. The private pool takes bee-rpc's own copy,
        # the one the Buffers of every call are made of.
        buffer_file = descriptor_pb2.FileDescriptorProto()
        buffer_pb2.DESCRIPTOR.CopyToProto(buffer_file)
        pool.Add(buffer_file)
        for proto in files.file:
            if proto.name != buffer_file.name:
                pool.Add(proto)

        def cls(name):
            return message_factory.GetMessageClass(pool.FindMessageTypeByName("celaut." + name))

        names = ("Client", "RecursionGuard", "Configuration", "Metadata", "Service",
                 "StartReference", "ServiceInstance", "TokenMessage", "Refund", "Metrics",
                 "EstimatedCost", "BalanceStatementRequest", "BalanceStatement", "Peer",
                 "BytesKeyValue", "Amount", "ConfigurationFile")
        m = SimpleNamespace(**{n: cls(n) for n in names})
        m.Hash = cls("Metadata.HashTag.Hash")
        m.Empty = buffer_pb2.Empty
        m.Buffer = buffer_pb2.Buffer
        _MESSAGES = m
        return m


def start_service_indices():
    m = messages()
    # protos/gateway_bee.py: StartService_input_indices. GetServiceEstimatedCost takes
    # the same request.
    return {1: m.Client, 2: m.RecursionGuard, 3: m.Configuration, 4: m.Hash,
            5: m.Metadata, 6: m.Service, 7: m.StartReference}


def amount(mu):
    return messages().Amount(n=str(int(mu)))


def mu(amount_message):
    return int(amount_message.n) if amount_message.n else 0


class GatewayError(Exception):
    """A gateway RPC failed. ``code`` is the gRPC status name, ``details`` the node's text."""

    def __init__(self, rpc, exc):
        self.rpc = rpc
        self.original = exc
        code = getattr(exc, "code", None)
        details = getattr(exc, "details", None)
        try:
            self.code = code().name if callable(code) else None
        except Exception:
            self.code = None
        try:
            self.details = details() if callable(details) else None
        except Exception:
            self.details = None
        super().__init__(f"{rpc} failed: {self.code or type(exc).__name__}: "
                         f"{self.details or exc}")


class _CountingMethod:
    """A gRPC stream-stream method that adds up the size of each request Buffer.

    The counts are what bee-rpc gives gRPC to send, the same measure as nodo's own
    test of the block skip (tests/test_start_service_block_skip_e2e.py).
    """

    def __init__(self, method):
        self.method = method
        self.request_bytes = 0
        self.call = None

    def __call__(self, request_iterator, timeout=None, **kwargs):
        def counted():
            for buffer in request_iterator:
                self.request_bytes += buffer.ByteSize()
                yield buffer
        self.call = self.method(counted(), timeout=timeout, **kwargs)
        return self.call


def _method(channel, rpc):
    from bee_rpc import buffer_pb2
    return channel.stream_stream(
        GATEWAY_SERVICE + rpc,
        request_serializer=buffer_pb2.Buffer.SerializeToString,
        response_deserializer=buffer_pb2.Buffer.FromString,
    )


def call_one(node_url, rpc, request, in_indices, out_indices, timeout=30, counter=None,
             block_skip=False):
    """One request message (or an iterator of them), the first answer message.

    ``counter`` is a list that gets the _CountingMethod of the call, for its bytes.
    """
    import grpc
    from bee_rpc.client import client_grpc
    channel = grpc.insecure_channel(node_url)
    method = _CountingMethod(_method(channel, rpc))
    if counter is not None:
        counter.append(method)
    try:
        return next(client_grpc(
            method=method,
            block_skip=block_skip,
            input=request,
            indices_serializer=in_indices,
            indices_parser=out_indices,
            partitions_message_mode_parser=True,
            timeout=timeout,
        ), None)
    except grpc.RpcError as e:
        raise GatewayError(rpc, e) from e
    finally:
        channel.close()


# ---------------------------------------------------------------------------
# A packed child service, as this service holds it
# ---------------------------------------------------------------------------
class PackedService:
    """A dependency that the packer put in this service's image.

    ``service/__services__/<hash>`` holds the Service (a bee-rpc directory: its parts
    and its blocks by reference) and ``service/__metadata__/<hash>`` its Metadata.
    """

    def __init__(self, service_hash, services_dir, metadata_dir):
        self.hash = service_hash
        self.service_path = os.path.join(services_dir, service_hash)
        self.metadata_path = os.path.join(metadata_dir, service_hash)

    def metadata(self):
        m = messages().Metadata()
        with open(self.metadata_path, "rb") as fh:
            m.ParseFromString(fh.read())
        return m

    def spec(self):
        """The Service with each block left as its pointer (wbp.bin), or a plain file.

        Enough to read every field but the filesystem, which is what a block holds.
        """
        candidates = ([os.path.join(self.service_path, "wbp.bin")]
                      if os.path.isdir(self.service_path) else [self.service_path])
        for path in candidates:
            if os.path.isfile(path):
                s = messages().Service()
                with open(path, "rb") as fh:
                    s.ParseFromString(fh.read())
                return s
        raise FileNotFoundError(f"no readable spec for {self.hash} in {self.service_path}")

    def request(self, config=None, start_ref=None, send_service=True, done=None):
        """The StartService (or GetServiceEstimatedCost) request, in nodo's order.

        The StartReference and the Configuration come before the hashes: the node may
        begin the start at the first hash it holds, and a field that arrives after
        that is ignored (celaut.proto, StartReference). ``done`` is set when the last
        message has been handed to bee-rpc.
        """
        from bee_rpc.client import Dir
        m = messages()
        try:
            if start_ref is not None:
                yield m.StartReference(ref=start_ref)
            if config is not None:
                yield config
            metadata = self.metadata()
            for h in metadata.hashtag.hash:
                yield m.Hash(type=h.type, value=h.value)
            if send_service:
                yield metadata
                yield Dir(dir=self.service_path, _type=m.Service)
        finally:
            if done is not None:
                done.set()


def configuration(initial_mu=None, envs=None):
    m = messages()
    config = m.Configuration()
    if initial_mu is not None:
        config.initial_mu.CopyFrom(amount(initial_mu))
    for key, value in (envs or {}).items():
        config.environment_variables.append(
            m.BytesKeyValue(key=key, value=value if isinstance(value, bytes) else value.encode()))
    return config


class StartResult(SimpleNamespace):
    """instance, request_bytes, seconds_to_instance, seconds_to_complete."""


# After the answer, a request that has not grown for this long is done: the node held
# the service and told the sender to stop (bee-rpc's signal), or asked it to skip the
# blocks it holds, and nothing more will be sent.
REQUEST_STILL_SECONDS = 1.0


def start_service(node_url, packed, *, config=None, start_ref=None, send_service=True,
                  block_skip=False, timeout=600, complete_timeout=120):
    """StartService for ``packed``; the instance and what the request cost on the wire.

    The node may answer before it has read the whole request (it starts at the first
    hash of a service it holds, and signals the sender to stop). So the call is kept
    open until bee-rpc has handed over the last message, or the call ended, or the
    request stopped growing for REQUEST_STILL_SECONDS, or ``complete_timeout`` passed:
    only then do the counted bytes say how much of the service went on the wire.
    ``seconds_to_complete`` is that moment.

    With ``block_skip`` the request honours the skip requests that the node sends for
    the blocks it holds (#371). bee-rpc then keeps the request direction open until the
    answer is done with, so the generator is closed here, as nodo's own client does.
    """
    import grpc
    from bee_rpc.client import client_grpc
    channel = grpc.insecure_channel(node_url)
    method = _CountingMethod(_method(channel, "StartService"))
    done = threading.Event()
    responses = client_grpc(
        method=method,
        input=packed.request(config=config, start_ref=start_ref,
                             send_service=send_service, done=done),
        indices_serializer=start_service_indices(),
        indices_parser={1: messages().ServiceInstance},
        partitions_message_mode_parser=True,
        timeout=timeout,
        block_skip=block_skip,
    )
    t0 = time.monotonic()
    try:
        instance = next(responses, None)
        t_instance = time.monotonic() - t0
        deadline = time.monotonic() + complete_timeout
        last, still_since = -1, time.monotonic()
        while not done.is_set() and time.monotonic() < deadline:
            if method.call is not None and method.call.done():
                break
            now = time.monotonic()
            if method.request_bytes != last:
                last, still_since = method.request_bytes, now
            elif now - still_since >= REQUEST_STILL_SECONDS:
                break
            time.sleep(0.02)
        t_complete = time.monotonic() - t0
        bytes_sent = method.request_bytes
    except grpc.RpcError as e:
        raise GatewayError("StartService", e) from e
    finally:
        responses.close()
        channel.close()
    if instance is None:
        raise GatewayError("StartService", RuntimeError("the node answered no ServiceInstance"))
    return StartResult(instance=instance, request_bytes=bytes_sent,
                       seconds_to_instance=round(t_instance, 3),
                       seconds_to_complete=round(t_complete, 3),
                       request_complete=done.is_set())


def stop_service(node_url, token, timeout=60):
    m = messages()
    refund = call_one(node_url, "StopService", m.TokenMessage(token=token),
                      {1: m.TokenMessage}, {1: m.Refund}, timeout=timeout)
    return mu(refund.amount) if refund is not None else 0


def estimated_cost(node_url, packed, config=None, timeout=120, measure=None):
    """The node's EstimatedCost. ``measure``, a dict, gets the request bytes and seconds.

    The service goes with the request, with the block skip on: a node that does not
    hold it reads it (and keeps it), and a node that holds it stops the sender.
    """
    m = messages()
    counter = []
    t0 = time.monotonic()
    cost = call_one(node_url, "GetServiceEstimatedCost",
                    packed.request(config=config), start_service_indices(),
                    {1: m.EstimatedCost}, timeout=timeout, counter=counter, block_skip=True)
    if measure is not None:
        measure.update(request_bytes=counter[0].request_bytes,
                       seconds=round(time.monotonic() - t0, 3))
    if cost is None:
        raise GatewayError("GetServiceEstimatedCost", RuntimeError("no EstimatedCost"))
    return cost


def metrics_balance(node_url, token, timeout=30):
    m = messages()
    out = call_one(node_url, "GetMetrics", m.TokenMessage(token=token),
                   {1: m.TokenMessage}, {1: m.Metrics}, timeout=timeout)
    return mu(out.balance) if out is not None else None


def peer_info(node_url, timeout=30):
    m = messages()
    # An empty Client: a local instance is exempt from the client gate, and bee-rpc
    # v0.0.1 cannot place a request with no message at an index.
    return call_one(node_url, "GetPeerInfo", m.Client(), {1: m.Client}, {1: m.Peer},
                    timeout=timeout)


def balance_statement(node_url, token="", from_seq=0, to_seq=0, timeout=60):
    m = messages()
    out = call_one(node_url, "GetBalanceStatement",
                   m.BalanceStatementRequest(token=token, from_seq=from_seq, to_seq=to_seq),
                   {1: m.BalanceStatementRequest, 2: m.Client}, {1: m.BalanceStatement},
                   timeout=timeout)
    if out is None:
        raise GatewayError("GetBalanceStatement", RuntimeError("no BalanceStatement"))
    return out


def full_statement(node_url, token="", from_seq=1, max_pages=50, timeout=60):
    """Every movement from ``from_seq`` to the head, page by page.

    A page that the node cut at its limit is the first rows of the range, so the next
    page asks from the last seq received (celaut.proto, BalanceStatement.movements).
    Returns the pages, each a signed statement.
    """
    pages = []
    seq = from_seq
    for _ in range(max_pages):
        page = balance_statement(node_url, token=token, from_seq=seq, timeout=timeout)
        pages.append(page)
        if not page.movements:
            break
        last = page.movements[-1].seq
        if last >= page.head_seq:
            break
        seq = last + 1
    return pages


def tunnel_http_get(node_url, token, slot, path, timeout=300, chunk_cb=None):
    """GET ``path`` from a slot of a child over ServiceTunnel; (status, headers, body).

    The request direction stays open until the whole answer arrived: for a TCP slot
    the node closes the write side of the connection to the service when the stream
    of the caller ends, and a server may take that as a client that went away.
    Returns also the bytes sent and received through the tunnel, which are what the
    node relays and charges (src/tunneling/rpc_tunnel.py).
    """
    import grpc
    from bee_rpc.client import client_grpc
    m = messages()
    request = (f"GET {path} HTTP/1.1\r\nHost: tunnel\r\nConnection: close\r\n\r\n").encode()
    finished = threading.Event()

    def outbound():
        yield m.TokenMessage(token=token, slot=str(slot))
        yield request
        finished.wait(timeout)

    channel = grpc.insecure_channel(node_url)
    received = bytearray()
    head, body_len, header_end = None, None, None
    t0 = time.monotonic()
    t_first = None
    try:
        # The payload is parsed in memory ({0: True}), as the node parses it: without
        # it bee-rpc writes each chunk to a file and yields a Dir.
        for chunk in client_grpc(method=_method(channel, "ServiceTunnel"), input=outbound(),
                                 indices_serializer={1: m.TokenMessage, 0: bytes},
                                 indices_parser={0: bytes},
                                 partitions_message_mode_parser={0: True}, timeout=timeout):
            if not isinstance(chunk, (bytes, bytearray)):
                continue
            if t_first is None:
                t_first = time.monotonic()
            received.extend(chunk)
            if header_end is None:
                i = received.find(b"\r\n\r\n")
                if i >= 0:
                    header_end = i + 4
                    head = bytes(received[:i]).decode("latin-1")
                    for line in head.split("\r\n")[1:]:
                        k, _, v = line.partition(":")
                        if k.strip().lower() == "content-length":
                            body_len = int(v.strip())
            if header_end is not None and body_len is not None \
                    and len(received) - header_end >= body_len:
                break
    except grpc.RpcError as e:
        raise GatewayError("ServiceTunnel", e) from e
    finally:
        finished.set()
        elapsed = time.monotonic() - t0
        channel.close()
    status = int(head.split(" ", 2)[1]) if head else None
    body = bytes(received[header_end:]) if header_end is not None else b""
    return SimpleNamespace(status=status, head=head, body_bytes=len(body), body=body[:256],
                           sent_bytes=len(request), received_bytes=len(received),
                           seconds=elapsed,
                           seconds_after_first_byte=(time.monotonic() - t_first) if t_first else None)


# ---------------------------------------------------------------------------
# Balance statements: nodo's reader rules, without nodo
# ---------------------------------------------------------------------------
# src/database/ledger.py
_MOVEMENT_PREFIX = "celaut-balance-movement:"
_GENESIS_PREFIX = "celaut-balance-genesis:"
_INSTANCE_PREFIX = "celaut-ledger-instance:"
_ACCOUNT_PREFIX = "celaut-ledger-account:"
# src/identity/node_identity.py
_STATEMENT_PREFIX = "celaut-balance-statement:"
# src/manager/statement_check.py
CLOCK_SKEW_SECONDS = 120


def _digest(text):
    return hashlib.blake2b(text.encode("utf-8"), digest_size=32).hexdigest()


def _hex(text):
    return text.encode("utf-8").hex()


def instance_ref(token):
    return _digest(_INSTANCE_PREFIX + token)


def account_ref(account):
    return _digest(_ACCOUNT_PREFIX + account)


def genesis_hash_of_ref(ref):
    return _digest(_GENESIS_PREFIX + ref)


def movement_hash(mv):
    return _digest(
        f"{_MOVEMENT_PREFIX}{mv.prev_hash}|{int(mv.seq)}~{int(mv.ts)}~"
        f"{_hex(str(int(mv.amount.n)))}~{_hex(str(int(mv.balance_after.n)))}~"
        f"{_hex(mv.kind)}~{mv.instance_ref or ''}~{_hex(mv.detail or '')}")


def statement_digest(st):
    text = "|".join((
        st.account_ref, str(st.from_seq), str(st.to_seq), str(st.ts), str(st.retention_days),
        str(st.oldest_seq), str(st.head_seq), st.head_hash, _hex(st.balance.n),
        "/".join(movement_hash(mv) for mv in st.movements),
    ))
    return _digest(text)


def statement_payload(peer_id, digest):
    return f"{_STATEMENT_PREFIX}{peer_id}|{digest}"


def verify_signature(st, peer_id):
    """Ed25519 (RFC 8032) by the node's public key over the statement payload.

    None when no Ed25519 implementation is installed: a signature that could not be
    checked is neither valid nor forged.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer_id))
        key.verify(bytes.fromhex(st.signature),
                   statement_payload(peer_id, statement_digest(st)).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _canonical(a):
    return isinstance(a.n, str) and a.n == str(int(a.n))


def detail_of(mv):
    try:
        parsed = json.loads(mv.detail) if mv.detail else {}
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def verify_chain(st, now, from_seq=1, previous=None):
    """The problems of one page, by the rules of nodo's ``verify_chain`` (none: valid).

    ``previous`` is the last movement of the page before, (seq, hash, balance_after),
    which this page must continue; None for the first page. Returns a list of
    (seq, problem) pairs.
    """
    problems = []
    mvs = list(st.movements)
    if abs(int(st.ts) - now) > CLOCK_SKEW_SECONDS:
        problems.append((None, f"the statement is dated {st.ts}, and it is {int(now)}"))
    if not all(_canonical(mv.amount) and _canonical(mv.balance_after) for mv in mvs) \
            or not _canonical(st.balance):
        problems.append((None, "an amount is not a canonical integer"))
        return problems
    hashes = [movement_hash(mv) for mv in mvs]
    for i, mv in enumerate(mvs):
        if i:
            before = mvs[i - 1]
            if mv.seq != before.seq + 1:
                problems.append((mv.seq, f"movements {before.seq + 1} to {mv.seq - 1} are missing"))
            if mv.prev_hash != hashes[i - 1]:
                problems.append((mv.seq, f"movement {mv.seq} does not hang from movement {before.seq}"))
            if int(before.balance_after.n) + int(mv.amount.n) != int(mv.balance_after.n):
                problems.append((mv.seq, f"movement {mv.seq} does not add up"))
        if int(mv.ts) > int(st.ts):
            problems.append((mv.seq, f"movement {mv.seq} is dated after the statement"))
    if mvs:
        first = mvs[0]
        if first.seq == 1:
            if first.prev_hash != genesis_hash_of_ref(st.account_ref):
                problems.append((1, "the first movement does not hang from the genesis of the account"))
            if int(first.amount.n) != int(first.balance_after.n):
                problems.append((1, "the first movement does not start from 0"))
        expected_first = max(from_seq, int(st.oldest_seq))
        if first.seq != expected_first:
            problems.append((first.seq, f"movements {expected_first} to {first.seq - 1} are held "
                                        "and not shown"))
        if previous is not None:
            p_seq, p_hash, p_balance = previous
            if first.seq == p_seq + 1:
                if first.prev_hash != p_hash:
                    problems.append((first.seq, f"movement {p_seq} is not the movement that it was"))
                if p_balance + int(first.amount.n) != int(first.balance_after.n):
                    problems.append((first.seq, f"movement {first.seq} does not add up from movement {p_seq}"))
        last = mvs[-1]
        if last.seq == st.head_seq:
            if hashes[-1] != st.head_hash:
                problems.append((last.seq, "the hash of the last movement is not the head"))
            if int(last.balance_after.n) != int(st.balance.n):
                problems.append((last.seq, "the balance is not the balance after the last movement"))
        elif last.seq > st.head_seq:
            problems.append((last.seq, "a movement is after the head"))
    elif int(st.head_seq) == 0:
        if int(st.balance.n) != 0 or st.head_hash != genesis_hash_of_ref(st.account_ref):
            problems.append((0, "an account with no movement holds a balance"))
    return problems


def verify_statement(pages, peer_id, now=None, from_seq=1):
    """Check a statement read page by page: signatures, chain, sum, head.

    Returns a dict with the counts and the problems found. ``signatures_ok`` is None
    when no page could be checked for want of an Ed25519 implementation.
    """
    now = time.time() if now is None else now
    out = {"pages": len(pages), "movements": 0, "problems": [], "signatures": []}
    previous = None
    seen = []
    for page in pages:
        out["signatures"].append(verify_signature(page, peer_id))
        for seq, problem in verify_chain(page, now, from_seq=from_seq if previous is None
                                         else previous[0] + 1, previous=previous):
            out["problems"].append({"seq": seq, "problem": problem})
        if pages[0].account_ref != page.account_ref:
            out["problems"].append({"seq": None, "problem": "a page is about another account"})
        for mv in page.movements:
            seen.append(mv)
        if page.movements:
            last = page.movements[-1]
            previous = (int(last.seq), movement_hash(last), int(last.balance_after.n))
    out["movements"] = len(seen)
    sigs = out["signatures"]
    out["signatures_ok"] = None if any(s is None for s in sigs) else all(sigs)
    last_page = pages[-1] if pages else None
    if seen and last_page is not None:
        out["account_ref"] = last_page.account_ref
        out["first_seq"] = int(seen[0].seq)
        out["last_seq"] = int(seen[-1].seq)
        out["head_seq"] = int(last_page.head_seq)
        out["balance_mu"] = int(last_page.balance.n)
        out["sum_mu"] = sum(int(mv.amount.n) for mv in seen)
        # From the first movement the sum of the amounts is the balance: the first one
        # starts from 0 (verify_chain rule 3).
        out["adds_up"] = (int(seen[0].seq) == 1 and out["sum_mu"] == int(seen[-1].balance_after.n)
                          and int(seen[-1].seq) == int(last_page.head_seq)
                          and int(seen[-1].balance_after.n) == out["balance_mu"])
    out["rows"] = seen
    return out


def rates_from_config(config_file):
    """The node's rates by name, from the gateway slot of ``/__config__``.

    ``ConfigurationFile.gateway`` is the node's gateway as the instance reaches it, and
    its api slots carry the rates of the node in ``mu_per_call`` (celaut.proto).
    """
    m = messages()
    cfg = m.ConfigurationFile()
    with open(config_file, "rb") as fh:
        cfg.ParseFromString(fh.read())
    rates = {}
    for slot in cfg.gateway.api.slot:
        for kv in slot.mu_per_call:
            try:
                rates[kv.key] = int(kv.value.n)
            except (TypeError, ValueError):
                pass
    return rates
