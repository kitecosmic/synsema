"""
Syntecnia Intentional Operations.

Instead of imperative loops, agents express WHAT they want, not HOW:

    apply double to each in numbers where value > 10
    transform users removing inactive
    collect names from users where active == true
    update products setting price to price * 0.9 where stock > 100

These operations are:
    - Declarative: express intent, not iteration
    - Optimizable: the runtime can parallelize or batch
    - Readable: a human or agent can understand at a glance
    - Composable: chain operations with pipes

Implementation: These compile to optimized operations on SynList/SynMap values.
They are registered as builtin tasks in the interpreter.
"""

from typing import List, Callable
from .types import (
    SynValue, SynTaskValue, BuiltinTask,
    syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
    SynList, SynMap, SynNumber, SynText, SynBool, SynNothing, SynTask,
)


def register_intentional_builtins(env, interpreter):
    """Register intentional operation builtins."""

    def _apply(args: List[SynValue]) -> SynValue:
        """
        apply(function, list) → new list with function applied to each element.

        Instead of:
            let result be []
            each item in items
                set result to append(result, transform(item))

        Write:
            let result be apply(transform, items)
        """
        func = args[0]
        collection = args[1]
        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"apply expects a list, got {collection.type.name}")
        results = []
        for item in collection.raw:
            result = interpreter._call_value(func, [item], None)
            results.append(result)
        return syn_list(results)

    def _where(args: List[SynValue]) -> SynValue:
        """
        where(list, predicate) → filtered list.

        Instead of:
            let result be []
            each item in items
                when condition(item)
                    set result to append(result, item)

        Write:
            let result be where(items, is_valid)
        """
        collection = args[0]
        predicate = args[1]
        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"where expects a list, got {collection.type.name}")
        results = []
        for item in collection.raw:
            check = interpreter._call_value(predicate, [item], None)
            if check.is_truthy():
                results.append(item)
        return syn_list(results)

    def _collect(args: List[SynValue]) -> SynValue:
        """
        collect(list, property_name) → list of property values.

        Instead of:
            let names be []
            each user in users
                set names to append(names, name of user)

        Write:
            let names be collect(users, "name")
        """
        collection = args[0]
        prop_name = str(args[1].raw)
        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"collect expects a list, got {collection.type.name}")
        results = []
        for item in collection.raw:
            if isinstance(item.type, SynMap) and prop_name in item.raw:
                results.append(item.raw[prop_name])
            else:
                results.append(syn_nothing())
        return syn_list(results)

    def _transform(args: List[SynValue]) -> SynValue:
        """
        transform(list, function, predicate?) → selectively transformed list.

        Applies function only to items matching predicate (or all if no predicate).

        transform(products, apply_discount)  -- all items
        transform(products, apply_discount, is_expensive)  -- only expensive
        """
        collection = args[0]
        func = args[1]
        predicate = args[2] if len(args) > 2 else None

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"transform expects a list, got {collection.type.name}")

        results = []
        for item in collection.raw:
            should_transform = True
            if predicate:
                check = interpreter._call_value(predicate, [item], None)
                should_transform = check.is_truthy()

            if should_transform:
                results.append(interpreter._call_value(func, [item], None))
            else:
                results.append(item)
        return syn_list(results)

    def _reduce(args: List[SynValue]) -> SynValue:
        """
        reduce(list, function, initial) → single value.

        Instead of:
            let total be 0
            each item in items
                set total to total + item

        Write:
            let total be reduce(items, add, 0)
        """
        collection = args[0]
        func = args[1]
        accumulator = args[2] if len(args) > 2 else syn_number(0)

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"reduce expects a list, got {collection.type.name}")

        for item in collection.raw:
            accumulator = interpreter._call_value(func, [accumulator, item], None)
        return accumulator

    def _sort_by(args: List[SynValue]) -> SynValue:
        """
        sort_by(list, key_function) → sorted list.

        let sorted_products be sort_by(products, get_price)
        """
        collection = args[0]
        key_func = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"sort_by expects a list, got {collection.type.name}")

        def sort_key(item):
            result = interpreter._call_value(key_func, [item], None)
            return result.raw if isinstance(result.type, (SynNumber, SynText)) else 0

        sorted_items = sorted(collection.raw, key=sort_key)
        return syn_list(sorted_items)

    def _group_by(args: List[SynValue]) -> SynValue:
        """
        group_by(list, key_function) → map of key → list.

        let by_category be group_by(products, get_category)
        """
        collection = args[0]
        key_func = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"group_by expects a list, got {collection.type.name}")

        groups = {}
        for item in collection.raw:
            key = interpreter._call_value(key_func, [item], None)
            key_str = str(key)
            if key_str not in groups:
                groups[key_str] = []
            groups[key_str].append(item)

        result = {}
        for k, v in groups.items():
            result[k] = syn_list(v)
        return syn_map(result)

    def _find_first(args: List[SynValue]) -> SynValue:
        """
        find_first(list, predicate) → first matching item or nothing.

        let admin be find_first(users, is_admin)
        """
        collection = args[0]
        predicate = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"find_first expects a list, got {collection.type.name}")

        for item in collection.raw:
            check = interpreter._call_value(predicate, [item], None)
            if check.is_truthy():
                return item
        return syn_nothing()

    def _every(args: List[SynValue]) -> SynValue:
        """
        every(list, predicate) → true if ALL items match.

        when every(orders, is_paid)
            ship_all(orders)
        """
        collection = args[0]
        predicate = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"every expects a list, got {collection.type.name}")

        for item in collection.raw:
            check = interpreter._call_value(predicate, [item], None)
            if not check.is_truthy():
                return syn_bool(False)
        return syn_bool(True)

    def _some(args: List[SynValue]) -> SynValue:
        """
        some(list, predicate) → true if ANY item matches.
        """
        collection = args[0]
        predicate = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"some expects a list, got {collection.type.name}")

        for item in collection.raw:
            check = interpreter._call_value(predicate, [item], None)
            if check.is_truthy():
                return syn_bool(True)
        return syn_bool(False)

    def _count_where(args: List[SynValue]) -> SynValue:
        """
        count_where(list, predicate) → number of matching items.
        """
        collection = args[0]
        predicate = args[1]

        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"count_where expects a list, got {collection.type.name}")

        count = 0
        for item in collection.raw:
            check = interpreter._call_value(predicate, [item], None)
            if check.is_truthy():
                count += 1
        return syn_number(count)

    def _flatten(args: List[SynValue]) -> SynValue:
        """
        flatten(list_of_lists) → single flat list.
        """
        collection = args[0]
        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"flatten expects a list, got {collection.type.name}")
        results = []
        for item in collection.raw:
            if isinstance(item.type, SynList):
                results.extend(item.raw)
            else:
                results.append(item)
        return syn_list(results)

    def _zip_with(args: List[SynValue]) -> SynValue:
        """
        zip_with(list_a, list_b, combiner) → combined list.
        """
        list_a = args[0]
        list_b = args[1]
        combiner = args[2]
        results = []
        for a, b in zip(list_a.raw, list_b.raw):
            results.append(interpreter._call_value(combiner, [a, b], None))
        return syn_list(results)

    # Register all
    builtins = {
        "apply": BuiltinTask("apply", _apply, 2),
        "where": BuiltinTask("where", _where, 2),
        "collect": BuiltinTask("collect", _collect, 2),
        "transform": BuiltinTask("transform", _transform),
        "reduce": BuiltinTask("reduce", _reduce),
        "sort_by": BuiltinTask("sort_by", _sort_by, 2),
        "group_by": BuiltinTask("group_by", _group_by, 2),
        "find_first": BuiltinTask("find_first", _find_first, 2),
        "every": BuiltinTask("every", _every, 2),
        "some": BuiltinTask("some", _some, 2),
        "count_where": BuiltinTask("count_where", _count_where, 2),
        "flatten": BuiltinTask("flatten", _flatten, 1),
        "zip_with": BuiltinTask("zip_with", _zip_with, 3),
    }

    from .types import SynTask as SynTaskType
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTaskType()))
