"""Persistence for Task 21's review queue. Thin, like Task 19's
`ProjectRevisionService`: gathering what a critique pass needs (model,
adjudications, gaps, assumptions) is API-layer composition; this service
only stores review items and their audit trail.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.review import ReviewAuditEntry, ReviewItemRecord
from app.services.assurance.critique import ReviewItem

STATUS_PENDING = "pending"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"


class ProjectNotFoundError(Exception):
    pass


class ReviewItemNotFoundError(Exception):
    pass


class ReviewItemAlreadyDecidedError(Exception):
    pass


class ProjectReviewService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _get_project(self, project_id: str) -> Project:
        result = await self.session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(project_id)
        return project

    async def create_review_items(
        self, project_id: str, revision_id: str | None, items: list[ReviewItem]
    ) -> list[ReviewItemRecord]:
        await self._get_project(project_id)
        records = []
        for item in items:
            record = ReviewItemRecord(
                id=item.id,
                project_id=project_id,
                revision_id=revision_id,
                category=item.category,
                severity=item.severity,
                rationale=item.rationale,
                cited_element_ids=list(item.cited_element_ids),
                cited_statement_ids=list(item.cited_statement_ids),
                status=STATUS_PENDING,
            )
            self.session.add(record)
            records.append(record)
            self.session.add(
                ReviewAuditEntry(review_item_id=item.id, action="created", reason=None)
            )
        await self.session.commit()
        for record in records:
            await self.session.refresh(record)
        return records

    async def get_item(self, project_id: str, item_id: str) -> ReviewItemRecord:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(ReviewItemRecord).where(
                ReviewItemRecord.id == item_id, ReviewItemRecord.project_id == project_id
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise ReviewItemNotFoundError(item_id)
        return record

    async def list_items(self, project_id: str, status: str | None = None) -> list[ReviewItemRecord]:
        await self._get_project(project_id)
        query = select(ReviewItemRecord).where(ReviewItemRecord.project_id == project_id)
        if status is not None:
            query = query.where(ReviewItemRecord.status == status)
        query = query.order_by(ReviewItemRecord.created_at.asc())
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def decide_item(
        self, project_id: str, item_id: str, decision: str, reason: str | None
    ) -> ReviewItemRecord:
        """`decision` is the verb ("accept"/"reject"); it is stored as the
        corresponding state ("accepted"/"rejected").

        Security-review finding, fixed here: this previously read the item,
        checked its status in Python, and only committed afterward -- two
        concurrent decide calls on the same item could both pass the
        "still pending" check before either commit, producing duplicate
        ReviewAuditEntry rows and (on the "accept" path) duplicate revision
        creation for what should be a single, terminal decision. The
        `UPDATE ... WHERE status = 'pending'` below makes the whole
        check-and-transition a single atomic statement: it claims exactly
        one row, or zero, never both callers.
        """
        await self._get_project(project_id)
        status = STATUS_ACCEPTED if decision == "accept" else STATUS_REJECTED
        result = await self.session.execute(
            update(ReviewItemRecord)
            .where(
                ReviewItemRecord.id == item_id,
                ReviewItemRecord.project_id == project_id,
                ReviewItemRecord.status == STATUS_PENDING,
            )
            .values(status=status, decision_reason=reason, decided_at=datetime.now(UTC))
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            await self.get_item(project_id, item_id)  # raises ReviewItemNotFoundError if truly missing
            raise ReviewItemAlreadyDecidedError(item_id)
        self.session.add(
            ReviewAuditEntry(review_item_id=item_id, action=status, reason=reason)
        )
        await self.session.commit()
        return await self.get_item(project_id, item_id)

    async def list_audit_entries(self, item_id: str) -> list[ReviewAuditEntry]:
        result = await self.session.execute(
            select(ReviewAuditEntry)
            .where(ReviewAuditEntry.review_item_id == item_id)
            .order_by(ReviewAuditEntry.created_at.asc())
        )
        return list(result.scalars().all())
