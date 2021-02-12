from c7n.registry import PluginRegistry
# from c7n.filters import (
from c7n.filters.core import (
    ValueFilter,
    Or,
    And,
    Not,
    EventFilter,
    ReduceFilter,
    CELFilter,
)
# from c7n.filters.cel import CELFilter
from c7n.exceptions import PolicyValidationError


class FilterRegistry(PluginRegistry):

    def __init__(self, *args, **kw):
        super(FilterRegistry, self).__init__(*args, **kw)
        self.register('value', ValueFilter)
        self.register('or', Or)
        self.register('and', And)
        self.register('not', Not)
        self.register('event', EventFilter)
        self.register('reduce', ReduceFilter)
        self.register('cel', CELFilter)

    def parse(self, data, manager):
        results = []
        for d in data:
            results.append(self.factory(d, manager))
        return results

    def factory(self, data, manager=None):
        """Factory func for filters.

        data - policy config for filters
        manager - resource type manager (ec2, s3, etc)
        """

        # Make the syntax a little nicer for common cases.
        if isinstance(data, dict) and len(data) == 1 and 'type' not in data:
            op = list(data.keys())[0]
            if op == 'or':
                return self['or'](data, self, manager)
            elif op == 'and':
                return self['and'](data, self, manager)
            elif op == 'not':
                return self['not'](data, self, manager)
            return ValueFilter(data, manager)
        if isinstance(data, str):
            filter_type = data
            data = {'type': data}
        else:
            filter_type = data.get('type')
        if not filter_type:
            raise PolicyValidationError(
                "%s Invalid Filter %s" % (
                    self.plugin_type, data))
        filter_class = self.get(filter_type)
        if filter_class is not None:
            return filter_class(data, manager)
        else:
            raise PolicyValidationError(
                "%s Invalid filter type %s" % (
                    self.plugin_type, data))