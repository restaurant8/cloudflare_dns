from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import SavedSnippet, User
from ..schemas import Message, SavedSnippetCreate, SavedSnippetOut, SavedSnippetUpdate


router = APIRouter(prefix="/snippets", tags=["snippets"])


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _snippet_from_payload(payload: SavedSnippetCreate) -> SavedSnippet:
    return SavedSnippet(
        title=payload.title.strip(),
        category=payload.category,
        address=_clean_text(payload.address),
        username=_clean_text(payload.username),
        port=payload.port,
        tags=_clean_text(payload.tags),
        content=_clean_text(payload.content),
        code=_clean_text(payload.code),
    )


@router.get("", response_model=list[SavedSnippetOut])
def list_snippets(q: str | None = None, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(SavedSnippet)
    if q and q.strip():
        keyword = f"%{q.strip()}%"
        query = query.filter(
            or_(
                SavedSnippet.title.like(keyword),
                SavedSnippet.category.like(keyword),
                SavedSnippet.address.like(keyword),
                SavedSnippet.username.like(keyword),
                SavedSnippet.tags.like(keyword),
                SavedSnippet.content.like(keyword),
                SavedSnippet.code.like(keyword),
            )
        )
    return query.order_by(SavedSnippet.updated_at.desc(), SavedSnippet.created_at.desc()).all()


@router.post("", response_model=SavedSnippetOut)
def create_snippet(payload: SavedSnippetCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    snippet = _snippet_from_payload(payload)
    db.add(snippet)
    db.commit()
    db.refresh(snippet)
    return snippet


@router.patch("/{snippet_id}", response_model=SavedSnippetOut)
def update_snippet(snippet_id: int, payload: SavedSnippetUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    snippet = db.get(SavedSnippet, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=404, detail="资料不存在")
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if key in {"title", "address", "username", "tags", "content", "code"}:
            setattr(snippet, key, _clean_text(value))
        else:
            setattr(snippet, key, value)
    db.commit()
    db.refresh(snippet)
    return snippet


@router.delete("/{snippet_id}", response_model=Message)
def delete_snippet(snippet_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    snippet = db.get(SavedSnippet, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=404, detail="资料不存在")
    db.delete(snippet)
    db.commit()
    return Message(message="资料已删除")
