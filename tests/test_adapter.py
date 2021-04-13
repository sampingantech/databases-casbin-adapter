from casbin import Enforcer
from databases import Database


def test_database(db: Database, enforcer: Enforcer):

    assert enforcer.enforce("alice", "data1", "read") == True
    assert enforcer.enforce("bob", "data2", "write") == True
    assert enforcer.enforce("alice", "data2", "read") == True
    assert enforcer.enforce("alice", "data2", "write") == True
    assert enforcer.enforce("alice", "data1", "write") == False
    assert enforcer.enforce("bob", "data1", "read") == False
    assert enforcer.enforce("bob", "data1", "write") == False
    assert enforcer.enforce("bob", "data2", "read") == False
