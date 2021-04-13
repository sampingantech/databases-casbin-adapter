from typing import List, Dict

from casbin import persist, Model
from databases import Database
from sqlalchemy import Table

from casbin_databases_adapter.utils import to_sync


class Filter:
    ptype: List[str] = []
    v0: List[str] = []
    v1: List[str] = []
    v2: List[str] = []
    v3: List[str] = []
    v4: List[str] = []
    v5: List[str] = []


class DatabasesAdapter(persist.Adapter):
    def __init__(self, db: Database, table: Table, filtered=False):
        self.db: Database = db
        self.table: Table = table
        self.filtered: bool = filtered

    @to_sync()
    async def load_policy(self, model: Model):
        query = self.table.select()
        rows = await self.db.fetch_all(query)
        for row in rows:
            # convert row from tuple to csv format and removing the first column (id)
            line = [i for i in row[1:] if i]
            persist.load_policy_line(", ".join(line), model)

    @to_sync()
    async def save_policy(self, model: Model):
        await self.db.execute(self.table.delete())
        query = self.table.insert()

        values: List = []
        for sec in ["p", "g"]:

            if sec not in model.model.keys():
                continue

            for p_type, assertion in model.model[sec].items():
                for rule in assertion.policy:
                    row = self._policy_to_dict(p_type, rule)
                    values.append(row)

        await self.db.execute_many(query, values)
        return True

    @to_sync()
    async def add_policy(self, sec, p_type, rule):
        row = self._policy_to_dict(p_type, rule)
        await self.db.execute(self.table.insert(), row)

    @to_sync()
    async def remove_policy(self, sec, p_type, rule):
        query = self.table.delete().where(self.table.columns.ptype == p_type)
        for i, value in enumerate(rule):
            query = query.where(self.table.columns[f"v{i}"] == value)

        result = await self.db.execute(query)

        return True if result > 0 else False

    @to_sync()
    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        query = self.table.select().where(self.table.columns.ptype == ptype)
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        for i, value in enumerate(field_values):
            if len(value) > 0:
                query = query.where(self.table.columns[f"v{field_index+1}"] == value)
        result = await self.db.execute(query)
        return True if result > 0 else False

    @to_sync()
    async def load_filtered_policy(self, model: Model, filter_: Filter) -> None:
        query = self.table.select().order_by(self.table.columns.id)
        for att, value in filter_.__dict__.items():
            if len(value) > 0:
                query = query.where(self.table.columns[att].in_(value))
        rows = await self.db.fetch_all(query)
        for row in rows:
            # convert row from tuple to csv format and removing the first column (id)
            line = [i for i in row[1:] if i]
            persist.load_policy_line(", ".join(line), model)

    def is_filtered(self):
        return self.filtered

    @staticmethod
    def _policy_to_dict(p_type: str, rule: List[str]) -> Dict[str, str]:
        row: dict = {"ptype": p_type}
        for i, value in enumerate(rule):
            row.update({f"v{i}": value})
        return row
