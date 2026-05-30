from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import User
from app.routes.target_pool import create_target_pool_item
from app.schemas import TargetPoolCreate


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def test_create_target_pool_item_detects_ipv6_and_keeps_remark():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()

    item = create_target_pool_item(
        TargetPoolCreate(target="2001:db8::5", port=22, remark="大陆备用"),
        user,
        db,
    )

    assert item.target == "2001:db8::5"
    assert item.target_type == "ipv6"
    assert item.port == 22
    assert item.remark == "大陆备用"
