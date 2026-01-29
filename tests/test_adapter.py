from casbin_pymongo_adapter._rule import CasbinRule
from casbin_pymongo_adapter import Filter, Adapter
from pymongo import MongoClient
from unittest import TestCase
import casbin

from tests.helper import get_fixture


def get_enforcer():
    adapter = Adapter("mongodb://localhost:27017", "casbin_test")
    e = casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)
    model = e.get_model()

    model.clear_policy()
    model.add_policy("p", "p", ["alice", "data1", "read"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["bob", "data2", "write"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "read"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "write"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("g", "g", ["alice", "data2_admin"])
    adapter.save_policy(model)

    return casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)


def clear_db(dbname):
    client = MongoClient("mongodb://localhost:27017")
    client.drop_database(dbname)


class TestConfig(TestCase):
    """
    unittest
    """

    def setUp(self):
        clear_db("casbin_test")

    def tearDown(self):
        clear_db("casbin_test")

    def test_enforcer_basic(self):
        """
        test policy
        """
        e = get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_add_policy(self):
        """
        test add_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test add_policy after insert 2 rules
        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_remove_policy(self):
        """
        test remove_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy after delete a role definition
        result = adapter.remove_policy(
            sec="g", ptype="g", rule=("alice", "data2_admin")
        )

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(result)

    def test_remove_policy_no_remove_when_rule_is_incomplete(self):
        adapter = Adapter("mongodb://localhost:27017", "casbin_test")
        e = casbin.Enforcer(get_fixture("rbac_with_resources_roles.conf"), adapter)

        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "read"))
        adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))
        adapter.add_policy(
            sec="p", ptype="p", rule=("data_group_admin", "data_group", "write")
        )
        adapter.add_policy(sec="g", ptype="g", rule=("alice", "data_group_admin"))
        adapter.add_policy(sec="g", ptype="g2", rule=("data2", "data_group"))

        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy doesn't remove when given an incomplete policy
        result = adapter.remove_policy(sec="p", ptype="p", rule=("alice", "data1"))
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(result)

    def test_save_policy(self):
        """
        test save_policy
        """

        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ("alice", "data4", "read"))

        adapter = e.get_adapter()
        adapter.save_policy(model)

        self.assertTrue(e.enforce("alice", "data4", "read"))

    def test_remove_filtered_policy(self):
        """
        test remove_filtered_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        result = adapter.remove_filtered_policy("g", "g", 6, "alice", "data2_admin")
        e.load_policy()
        self.assertFalse(result)

        result = adapter.remove_filtered_policy(
            "g", "g", 0, *[f"v{i}" for i in range(7)]
        )
        e.load_policy()
        self.assertFalse(result)

        result = adapter.remove_filtered_policy("g", "g", 0, "alice", "data2_admin")
        e.load_policy()
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
        e = get_enforcer()
        filter = Filter()

        filter.ptype = ["p"]
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e.load_filtered_policy(filter)
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
        e = get_enforcer()
        filter = Filter()
        filter.raw_query = {"ptype": "p", "v0": {"$in": ["alice", "bob"]}}

        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    async def test_update_policy(self):
        e = get_enforcer()
        example_p = ["mike", "cookie", "eat"]

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.update_policy(["alice", "data1", "read"], ["alice", "data1", "no_read"])
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        e.add_policy(example_p)
        e.update_policy(example_p, ["bob", "data1", "read"])
        self.assertTrue(e.enforce("bob", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "write"))
        e.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
        self.assertTrue(e.enforce("bob", "data1", "write"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        e.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("bob", "data2", "read"))
        e.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("carl", "data2", "write"))
        e.update_policy(["carl", "data2", "write"], ["carl", "data2", "no_write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

    async def test_update_policies(self):
        e = get_enforcer()

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

        e.update_policies(old_rules, new_rules)

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data_test", "read"))

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data_test", "write"))

        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "read"))

        self.assertFalse(e.enforce("data2_admin", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "write"))

    def test_str(self):
        """
        test __str__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(rule.__str__(), "p, alice, data1, read")

    def test_dict(self):
        """
        test __str__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(
            rule.dict(), {"ptype": "p", "v0": "alice", "v1": "data1", "v2": "read"}
        )

    def test_repr(self):
        """
        test __repr__ function
        """
        adapter = Adapter("mongodb://localhost:27017", "casbin_test")
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule :"p, alice, data1, read">')
        # adapter.save_policy(rule)
        # self.assertRegex(repr(rule), r'<CasbinRule :"p, alice, data1, read">')

    def test_adapter_with_existing_client(self):
        """
        test adapter with existing MongoClient using client parameter
        """
        # Create a MongoClient instance
        client = MongoClient("mongodb://localhost:27017")
        
        # Create adapter with existing client
        adapter = Adapter(client=client, db_name="casbin_test")
        
        e = casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)
        model = e.get_model()

        model.clear_policy()
        model.add_policy("p", "p", ["alice", "data1", "read"])
        adapter.save_policy(model)

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        
        # Clean up
        client.drop_database("casbin_test")
        client.close()

    def test_adapter_with_existing_client_and_dbname(self):
        """
        test adapter with existing MongoClient using dbname parameter for backward compatibility
        """
        # Create a MongoClient instance
        client = MongoClient("mongodb://localhost:27017")
        
        # Create adapter with existing client using dbname instead of db_name
        adapter = Adapter(client=client, dbname="casbin_test")
        
        e = casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)
        model = e.get_model()

        model.clear_policy()
        model.add_policy("p", "p", ["bob", "data2", "write"])
        adapter.save_policy(model)

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        
        # Clean up
        client.drop_database("casbin_test")
        client.close()

    def test_adapter_with_client_requires_db_name(self):
        """
        test that adapter with client parameter requires db_name or dbname
        """
        client = MongoClient("mongodb://localhost:27017")
        
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(client=client)
        
        self.assertIn("db_name or dbname must be provided", str(context.exception))
        client.close()

    def test_adapter_without_client_requires_uri(self):
        """
        test that adapter without client parameter requires uri
        """
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(dbname="casbin_test")
        
        self.assertIn("uri must be provided", str(context.exception))

    def test_adapter_without_client_requires_dbname(self):
        """
        test that adapter without client parameter requires dbname
        """
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(uri="mongodb://localhost:27017")
        
        self.assertIn("dbname must be provided", str(context.exception))
