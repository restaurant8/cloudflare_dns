from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import User
from app.routes.snippets import create_snippet, delete_snippet, list_snippets, update_snippet
from app.schemas import SavedSnippetCreate, SavedSnippetUpdate


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def make_user(db):
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_create_update_search_and_delete_snippet():
    db = make_session()
    user = make_user(db)

    snippet = create_snippet(
        SavedSnippetCreate(
            title="香港 SSH",
            category="ssh",
            address="192.0.2.10",
            username="root",
            port=2222,
            tags="香港 宝塔",
            content="登录后查看 Nginx",
            code="systemctl status nginx",
        ),
        user,
        db,
    )

    assert snippet.id is not None
    assert snippet.address == "192.0.2.10"
    assert list_snippets("宝塔", user, db)[0].id == snippet.id

    updated = update_snippet(snippet.id, SavedSnippetUpdate(title="香港 SSH 入口", port=22), user, db)

    assert updated.title == "香港 SSH 入口"
    assert updated.port == 22

    delete_snippet(snippet.id, user, db)

    assert list_snippets(None, user, db) == []
