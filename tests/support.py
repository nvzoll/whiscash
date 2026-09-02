from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.db.models import RefreshToken, ServiceClient, User
from app.repository.protocols import RefreshTokenRepo, ServiceClientRepo
from app.service.opaque_token import OpaqueToken


async def seed_session(refresh_token_repo: RefreshTokenRepo, user: User) -> UUID:
    token_id = uuid4()
    await refresh_token_repo.add(
        RefreshToken(
            id=token_id,
            user_id=user.id,
            family_id=uuid4(),
            token_hash="test-token-hash",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
        )
    )
    return token_id


async def seed_service_client(
    service_client_repo: ServiceClientRepo,
    *,
    name: str = "test-consumer",
    revoked: bool = False,
) -> tuple[ServiceClient, str]:
    key = OpaqueToken.generate_secret()
    client = ServiceClient(
        id=uuid4(),
        name=name,
        key_hash=OpaqueToken.hash_secret(key),
        revoked_at=datetime.now(UTC) if revoked else None,
        created_at=datetime.now(UTC),
    )
    await service_client_repo.add(client)
    return client, key
