from casbin import persist
from pymongo import MongoClient

from ._rule import CasbinRule


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(
        self,
        uri,
        dbname,
        collection="casbin_rule",
        filtered=False,
    ):
        """Create an adapter for Mongodb

        Args:
            uri (str): This should be the same requiement as pymongo Client's 'uri' parameter.
                          See https://pymongo.readthedocs.io/en/stable/api/pymongo/mongo_client.html#pymongo.mongo_client.MongoClient.
            dbname (str): Database to store policy.
            collection (str, optional): Collection of the choosen database. Defaults to "casbin_rule".
            filtered (bool, optional): Whether to use filtered query. Defaults to False.
        """
        client = MongoClient(uri)
        db = client[dbname]
        self._collection = db[collection]
        self._filtered = filtered

    def is_filtered(self):
        return self._filtered

    def load_policy(self, model):
        """Implementing add Interface for casbin. Load all policy rules from mongodb

        Args:
            model (CasbinRule): CasbinRule object
        """

        for line in self._collection.find():
            if "ptype" not in line:
                continue
            rule = CasbinRule(line["ptype"])
            for key, value in line.items():
                setattr(rule, key, value)

            persist.load_policy_line(str(rule), model)

    def load_filtered_policy(self, model, filter):
        """Load filtered policy rules from mongodb

        Args:
            model (CasbinRule): CasbinRule object
            filter (Filter): Filter rule object
        """
        query = {}
        if getattr(filter, "raw_query", None) is None:
            for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
                if len(getattr(filter, attr)) > 0:
                    value = getattr(filter, attr)
                    query[attr] = {"$in": value}
        else:
            query = getattr(filter, "raw_query")

        for line in self._collection.find(query):
            if "ptype" not in line:
                continue
            rule = CasbinRule(line["ptype"])
            for key, value in line.items():
                setattr(rule, key, value)

            persist.load_policy_line(str(rule), model)
        self._filtered = True

    def _save_policy_line(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        for index, value in enumerate(rule):
            setattr(line, f"v{index}", value)
        self._collection.insert_one(line.dict())

    def _find_policy_lines(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        for index, value in enumerate(rule):
            setattr(line, f"v{index}", value)
        return self._collection.find(line.dict())

    def _delete_policy_lines(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        for index, value in enumerate(rule):
            setattr(line, f"v{index}", value)

        # if rule is empty, do nothing
        # else find all given rules and delete them
        if len(line.dict()) == 0:
            return 0
        else:
            line_dict = line.dict()
            line_dict_keys_len = len(line_dict)
            results = self._collection.find(line_dict)
            to_delete = [
                result["_id"]
                for result in results
                if line_dict_keys_len == len(result.keys()) - 1
            ]
            results = self._collection.delete_many({"_id": {"$in": to_delete}})
            return results.deleted_count

    def save_policy(self, model) -> bool:
        """Implement add Interface for casbin. Save the policy in mongodb

        Args:
            model (Class Model): Casbin Model which loads from .conf file usually.

        Returns:
            bool: True if succeed
        """
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)
        return True

    def add_policy(self, sec, ptype, rule):
        """Add policy rules to mongodb

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rule (CasbinRule): Casbin rule will be added

        Returns:
            bool: True if succeed else False
        """
        self._save_policy_line(ptype, rule)
        return True

    def remove_policy(self, sec, ptype, rule):
        """Remove policy rules in mongodb(rules duplicate are also removed)

        Args:
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rule (CasbinRule): Casbin rule if it is exactly same as will be removed.

        Returns:
            Number: Number of policies be removed
        """
        deleted_count = self._delete_policy_lines(ptype, rule)
        return deleted_count > 0

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """Remove policy rules taht match the filter from the storage.
           This is part of the Auto-Save feature.

        Args:
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rule (CasbinRule): Casbin rule will be removed
            field_index (int): The policy index at which the filed_values begins filtering. Its range is [0, 5]
            field_values(List[str]): A list of rules to filter policy which starts from

        Returns:
            bool: True if succeed else False
        """
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        query = {
            f"v{index + field_index}": value
            for index, value in enumerate(field_values)
            if value != ""
        }
        query["ptype"] = ptype
        results = self._collection.delete_many(query)
        return results.deleted_count > 0

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """Update the old_rule with the new_rule in the database (storage).

        Args:
            sec (str): section type
            ptype (str): policy type
            old_rule (list[str]): the old rule that needs to be modified
            new_rule (list[str]): the new rule to replace the old rule
        """
        filter_query = {}
        for index, value in enumerate(old_rule):
            filter_query[f"v{index}"] = value

        self._collection.find_one_and_update(
            filter_query,
            {"$set": {f"v{index}": value for index, value in enumerate(new_rule)}},
        )

        return None
