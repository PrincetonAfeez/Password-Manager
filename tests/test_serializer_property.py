"""Test serializer property functionality."""

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from password_manager.models import Entry, KDFParams, VaultBody, VaultHeader
from password_manager.schema import VaultSchema
from password_manager.serializer import VaultSerializer


@st.composite
def vault_headers(draw):
    salt = draw(st.binary(min_size=16, max_size=16))
    n = draw(st.sampled_from([2**14, 2**15, 2**16]))
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return VaultHeader(
        salt=salt,
        kdf_params=KDFParams(n=n),
        revision=draw(st.integers(min_value=0, max_value=100)),
        created_at=created,
        updated_at=created,
    )


@st.composite
def vault_bodies(draw):
    entry = Entry(
        id="12345678-1234-5678-1234-567812345678",
        service=draw(st.text(min_size=1, max_size=32, alphabet="ab")),
        username=draw(st.text(min_size=1, max_size=32, alphabet="cd")),
        password=draw(st.text(min_size=1, max_size=32, alphabet="ef")),
        url="",
        notes="",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    return VaultBody(entries=[entry])


@settings(max_examples=25)
@given(header=vault_headers())
def test_header_round_trip(header: VaultHeader):
    serializer = VaultSerializer()
    schema = VaultSchema()
    schema.validate_header(header)
    loaded = serializer.loads_header(serializer.dumps_header(header))
    assert loaded.salt == header.salt
    assert loaded.revision == header.revision
    assert loaded.kdf_params.n == header.kdf_params.n


@settings(max_examples=25)
@given(body=vault_bodies())
def test_body_round_trip(body: VaultBody):
    serializer = VaultSerializer()
    schema = VaultSchema()
    schema.validate_body(body)
    loaded = serializer.loads_body(serializer.dumps_body(body))
    assert len(loaded.entries) == 1
    assert loaded.entries[0].service == body.entries[0].service
