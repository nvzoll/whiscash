import pytest
from sqlalchemy.exc import IntegrityError

from app.repository.protocols import ServiceClientRepo
from tests.support import seed_service_client


async def test_second_active_key_with_same_name_is_rejected(
    db_backend: str,
    service_client_repo: ServiceClientRepo,
) -> None:
    if db_backend != "postgres":
        pytest.skip("the partial unique index on service_client.name is enforced only by Postgres")

    await seed_service_client(service_client_repo, name="billing-svc")

    with pytest.raises(IntegrityError):
        await seed_service_client(service_client_repo, name="billing-svc")


async def test_name_is_reusable_once_the_previous_key_is_revoked(
    db_backend: str,
    service_client_repo: ServiceClientRepo,
) -> None:
    if db_backend != "postgres":
        pytest.skip("the partial unique index on service_client.name is enforced only by Postgres")

    revoked, _ = await seed_service_client(service_client_repo, name="billing-svc", revoked=True)

    reminted, _ = await seed_service_client(service_client_repo, name="billing-svc")

    assert reminted.id != revoked.id
