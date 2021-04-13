import asyncio
from asyncio import Task
import functools
from typing import List, Dict

from casbin import persist, Model
from databases import Database
from sqlalchemy import Table
import nest_asyncio


class DatabasesAdapter(persist.Adapter):
    def __init__(self, db: Database, table: Table, filtered=False):
        self.db: Database = db
        self.table: Table = table
        self.filtered: bool = filtered

    def load_policy(self, model: Model):
        asyncio_run(self.load_policy_async(model))

    async def load_policy_async(self, model: Model):
        query = self.table.select()
        rows = await self.db.fetch_all(query)
        for row in rows:
            # convert row from tuple to csv format and removing the first column (id)
            line = [i for i in row[1:] if i]
            line = ", ".join(line)
            persist.load_policy_line(line, model)

    def save_policy(self, model: Model):
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(None, self.save_policy_async, model)

    async def save_policy_async(self, model: Model):
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

    def add_policy(self, sec, ptype, rule):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.add_policy_async(sec, ptype, rule))

    async def add_policy_async(self, sec, p_type, rule):
        row = self._policy_to_dict(p_type, rule)
        await self.db.execute(self.table.insert(), row)

    def remove_policy(self, sec, ptype, rule):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.remove_policy_async(sec, ptype, rule))

    async def remove_policy_async(self, sec, p_type, rule):
        query = self.table.delete().where(self.table.c.ptype == p_type)
        for i, value in enumerate(rule):
            query = query.where(self.table.columns[f"v{i}"] == value)

        result = await self.db.execute(query)

        return True if result > 0 else False

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.remove_filtered_policy_async(sec, ptype, field_index, *field_values)
        )

    async def remove_filtered_policy_async(
        self, sec, ptype, field_index, *field_values
    ):
        query = self.table.select().where(self.table.columns.ptype == ptype)
        if not (0 <= field_index <= 0):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        for i, value in enumerate(field_values):
            if len(value) > 0:
                query = query.where(self.table.columns[f"v{field_index+1}"] == value)
        result = await self.db.execute(query)
        return True if result > 0 else False

    @staticmethod
    def _policy_to_dict(p_type: str, rule: str) -> Dict[str, str]:
        row: dict = {"ptype": p_type}
        for i, value in enumerate(rule):
            row.update({f"v{i}": value})
        return row
