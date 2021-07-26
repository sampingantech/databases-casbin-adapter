from casbin import Enforcer, Model, Adapter
from databases import Database

from casbin_databases_adapter.adapter import Filter


async def test_load_policy(db: Database, enforcer: Enforcer):

    assert enforcer.enforce("alice", "data1", "read") == True
    assert enforcer.enforce("bob", "data2", "write") == True
    assert enforcer.enforce("alice", "data2", "read") == True
    assert enforcer.enforce("alice", "data2", "write") == True
    assert enforcer.enforce("alice", "data1", "write") == False
    assert enforcer.enforce("bob", "data1", "read") == False
    assert enforcer.enforce("bob", "data1", "write") == False
    assert enforcer.enforce("bob", "data2", "read") == False


async def test_add_policy(db: Database, enforcer: Enforcer):
    assert not enforcer.enforce("eve", "data3", "read")
    result = await enforcer.add_permission_for_user("eve", "data3", "read")
    assert result
    assert enforcer.enforce("eve", "data3", "read")


async def test_save_policy(db: Database, enforcer: Enforcer):
    assert not enforcer.enforce("alice", "data4", "read")

    model: Model = enforcer.get_model()
    model.clear_policy()

    model.add_policy("p", "p", ["alice", "data4", "read"])
    adapter: Adapter = enforcer.get_adapter()
    await adapter.save_policy(model)
    assert enforcer.enforce("alice", "data4", "read")


async def test_remove_policy(db: Database, enforcer: Enforcer):
    assert not (enforcer.enforce("alice", "data5", "read"))
    await enforcer.add_permission_for_user("alice", "data5", "read")
    assert enforcer.enforce("alice", "data5", "read")
    await enforcer.delete_permission_for_user("alice", "data5", "read")
    assert not (enforcer.enforce("alice", "data5", "read"))


async def test_remove_filtered_policy(db: Database, enforcer: Enforcer):

    assert enforcer.enforce("alice", "data1", "read")
    await enforcer.remove_filtered_policy(1, "data1")
    assert not (enforcer.enforce("alice", "data1", "read"))

    assert enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("alice", "data2", "read")
    assert enforcer.enforce("alice", "data2", "write")

    await enforcer.remove_filtered_policy(1, "data2", "read")

    assert enforcer.enforce("bob", "data2", "write")
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert enforcer.enforce("alice", "data2", "write")

    await enforcer.remove_filtered_policy(2, "write")

    assert not (enforcer.enforce("bob", "data2", "write"))
    assert not (enforcer.enforce("alice", "data2", "write"))


async def test_filtered_policy(db: Database, enforcer: Enforcer):
    filter = Filter()

    filter.ptype = ["p"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert enforcer.enforce("bob", "data2", "write")

    filter.ptype = []
    filter.v0 = ["alice"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert not (enforcer.enforce("bob", "data2", "write"))
    assert not (enforcer.enforce("data2_admin", "data2", "read"))
    assert not (enforcer.enforce("data2_admin", "data2", "write"))

    filter.v0 = ["bob"]
    await enforcer.load_filtered_policy(filter)
    assert not (enforcer.enforce("alice", "data1", "read"))
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert enforcer.enforce("bob", "data2", "write")
    assert not (enforcer.enforce("data2_admin", "data2", "read"))
    assert not (enforcer.enforce("data2_admin", "data2", "write"))

    filter.v0 = ["data2_admin"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert not (enforcer.enforce("alice", "data1", "read"))
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert not (enforcer.enforce("bob", "data2", "write"))

    filter.v0 = ["alice", "bob"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert enforcer.enforce("bob", "data2", "write")
    assert not (enforcer.enforce("data2_admin", "data2", "read"))
    assert not (enforcer.enforce("data2_admin", "data2", "write"))

    filter.v0 = []
    filter.v1 = ["data1"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert not (enforcer.enforce("bob", "data2", "write"))
    assert not (enforcer.enforce("data2_admin", "data2", "read"))
    assert not (enforcer.enforce("data2_admin", "data2", "write"))

    filter.v1 = ["data2"]
    await enforcer.load_filtered_policy(filter)
    assert not (enforcer.enforce("alice", "data1", "read"))
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data2", "write")

    filter.v1 = []
    filter.v2 = ["read"]
    await enforcer.load_filtered_policy(filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert not (enforcer.enforce("bob", "data2", "write"))
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert not (enforcer.enforce("data2_admin", "data2", "write"))

    filter.v2 = ["write"]
    await enforcer.load_filtered_policy(filter)
    assert not (enforcer.enforce("alice", "data1", "read"))
    assert not (enforcer.enforce("alice", "data1", "write"))
    assert not (enforcer.enforce("alice", "data2", "read"))
    assert not (enforcer.enforce("alice", "data2", "write"))
    assert not (enforcer.enforce("bob", "data1", "read"))
    assert not (enforcer.enforce("bob", "data1", "write"))
    assert not (enforcer.enforce("bob", "data2", "read"))
    assert enforcer.enforce("bob", "data2", "write")
    assert not (enforcer.enforce("data2_admin", "data2", "read"))
    assert enforcer.enforce("data2_admin", "data2", "write")
