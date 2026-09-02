from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.db.models import RefreshToken, User
from app.repository.protocols import RefreshTokenRepo


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
