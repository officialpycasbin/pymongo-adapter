from casbin_pymongo_adapter.asynchronous import Adapter
from casbin_pymongo_adapter import Filter
from pymongo import AsyncMongoClient
from unittest import IsolatedAsyncioTestCase
import casbin

from tests.helper import get_fixture


async def get_enforcer():
    adapter = Adapter("mongodb://localhost:27017", "casbin_test")
    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    model = e.get_model()

    model.clear_policy()
    model.add_policy("p", "p", ["alice", "data1", "read"])
    model.add_policy("p", "p", ["bob", "data2", "write"])
    model.add_policy("p", "p", ["data2_admin", "data2", "read"])
    model.add_policy("p", "p", ["data2_admin", "data2", "write"])
    model.add_policy("g", "g", ["alice", "data2_admin"])
    await adapter.save_policy(model)

    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    await e.load_policy()
    return e


async def clear_db(dbname):
    client = AsyncMongoClient("mongodb://localhost:27017")
    await client.drop_database(dbname)


class TestConfig(IsolatedAsyncioTestCase):
    """
    unittest
    """

    async def asyncSetUp(self):
        await clear_db("casbin_test")

    async def asyncTearDown(self):
        await clear_db("casbin_test")

    async def test_enforcer_basic(self):
        """
        test policy
        """
        e = await get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_add_policy(self):
        """
        test add_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test add_policy after insert 2 rules
        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        await adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_remove_policy(self):
        """
        test remove_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy after delete a role definition
        result = await adapter.remove_policy(
            sec="g", ptype="g", rule=("alice", "data2_admin")
        )

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(result)

    async def test_remove_policy_no_remove_when_rule_is_incomplete(self):
        adapter = Adapter("mongodb://localhost:27017", "casbin_test")
        e = casbin.AsyncEnforcer(get_fixture("rbac_with_resources_roles.conf"), adapter)

        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "read"))
        await adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))
        await adapter.add_policy(
            sec="p", ptype="p", rule=("data_group_admin", "data_group", "write")
        )
        await adapter.add_policy(sec="g", ptype="g", rule=("alice", "data_group_admin"))
        await adapter.add_policy(sec="g", ptype="g2", rule=("data2", "data_group"))

        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy doesn't remove when given an incomplete policy
        result = await adapter.remove_policy(
            sec="p", ptype="p", rule=("alice", "data1")
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(result)

    async def test_save_policy(self):
        """
        test save_policy
        """

        e = await get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ("alice", "data4", "read"))

        adapter = e.get_adapter()
        await adapter.save_policy(model)

        self.assertTrue(e.enforce("alice", "data4", "read"))

    async def test_remove_filtered_policy(self):
        """
        test remove_filtered_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        result = await adapter.remove_filtered_policy(
            "g", "g", 6, "alice", "data2_admin"
        )
        await e.load_policy()
        self.assertFalse(result)

        result = await adapter.remove_filtered_policy(
            "g", "g", 0, *[f"v{i}" for i in range(7)]
        )
        await e.load_policy()
        self.assertFalse(result)

        result = await adapter.remove_filtered_policy(
            "g", "g", 0, "alice", "data2_admin"
        )
        await e.load_policy()
        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_filtered_policy(self):
        """
        test filtered_policy
        """
        e = await get_enforcer()
        filter = Filter()

        filter.ptype = ["p"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

        filter.ptype = []
        filter.v0 = ["alice"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["bob"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["data2_admin"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

        filter.v0 = ["alice", "bob"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = []
        filter.v1 = ["data1"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = ["data2"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = []
        filter.v2 = ["read"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v2 = ["write"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

    async def test_filtered_policy_with_raw_query(self):
        """
        test filtered_policy
        """
        e = await get_enforcer()
        filter = Filter()
        filter.raw_query = {"ptype": "p", "v0": {"$in": ["alice", "bob"]}}

        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    async def test_update_policy(self):
        e = await get_enforcer()
        example_p = ["mike", "cookie", "eat"]

        self.assertTrue(e.enforce("alice", "data1", "read"))
        await e.update_policy(["alice", "data1", "read"], ["alice", "data1", "no_read"])
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        await e.add_policy(example_p)
        await e.update_policy(example_p, ["bob", "data1", "read"])
        self.assertTrue(e.enforce("bob", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "write"))
        await e.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
        self.assertTrue(e.enforce("bob", "data1", "write"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        await e.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("bob", "data2", "read"))
        await e.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("carl", "data2", "write"))
        await e.update_policy(["carl", "data2", "write"], ["carl", "data2", "no_write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

    async def test_update_policies(self):
        e = await get_enforcer()

        old_rule_0 = ["alice", "data1", "read"]
        old_rule_1 = ["bob", "data2", "write"]
        old_rule_2 = ["data2_admin", "data2", "read"]
        old_rule_3 = ["data2_admin", "data2", "write"]

        new_rule_0 = ["alice", "data_test", "read"]
        new_rule_1 = ["bob", "data_test", "write"]
        new_rule_2 = ["data2_admin", "data_test", "read"]
        new_rule_3 = ["data2_admin", "data_test", "write"]

        old_rules = [old_rule_0, old_rule_1, old_rule_2, old_rule_3]
        new_rules = [new_rule_0, new_rule_1, new_rule_2, new_rule_3]

        await e.update_policies(old_rules, new_rules)

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data_test", "read"))

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data_test", "write"))

        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "read"))

        self.assertFalse(e.enforce("data2_admin", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "write"))

    async def test_adapter_with_existing_client(self):
        """
        test adapter with existing AsyncMongoClient using client parameter
        """
        # Create an AsyncMongoClient instance
        client = AsyncMongoClient("mongodb://localhost:27017")
        
        try:
            # Create adapter with existing client
            adapter = Adapter(client=client, db_name="casbin_test")
            
            e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
            model = e.get_model()

            model.clear_policy()
            model.add_policy("p", "p", ["alice", "data1", "read"])
            await adapter.save_policy(model)

            # reload policies from database
            await e.load_policy()

            self.assertTrue(e.enforce("alice", "data1", "read"))
            self.assertFalse(e.enforce("alice", "data1", "write"))
            
            # Clean up
            await client.drop_database("casbin_test")
        finally:
            client.close()

    async def test_adapter_with_existing_client_and_dbname(self):
        """
        test adapter with existing AsyncMongoClient using dbname parameter for backward compatibility
        """
        # Create an AsyncMongoClient instance
        client = AsyncMongoClient("mongodb://localhost:27017")
        
        try:
            # Create adapter with existing client using dbname instead of db_name
            adapter = Adapter(client=client, dbname="casbin_test")
            
            e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
            model = e.get_model()

            model.clear_policy()
            model.add_policy("p", "p", ["bob", "data2", "write"])
            await adapter.save_policy(model)

            # reload policies from database
            await e.load_policy()

            self.assertTrue(e.enforce("bob", "data2", "write"))
            self.assertFalse(e.enforce("bob", "data2", "read"))
            
            # Clean up
            await client.drop_database("casbin_test")
        finally:
            client.close()

    async def test_adapter_with_client_requires_db_name(self):
        """
        test that adapter with client parameter requires db_name or dbname
        """
        client = AsyncMongoClient("mongodb://localhost:27017")
        
        try:
            with self.assertRaises(ValueError) as context:
                adapter = Adapter(client=client)
            
            self.assertIn("db_name or dbname must be provided", str(context.exception))
        finally:
            client.close()

    async def test_adapter_without_client_requires_uri(self):
        """
        test that adapter without client parameter requires uri
        """
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(dbname="casbin_test")
        
        self.assertIn("uri must be provided", str(context.exception))

    async def test_adapter_without_client_requires_dbname(self):
        """
        test that adapter without client parameter requires dbname
        """
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(uri="mongodb://localhost:27017")
        
        self.assertIn("dbname must be provided", str(context.exception))
