from rpc_ac.utils import convert


def iextract_fields(iterable, fields, default=None):
    return ({field: elem.get(field, default) for field in fields} for elem in iterable)


def isearch_for_ids(interface, query=None, filters=None, sort='mod_time asc'):
    count = 1
    result = set()
    part = {'entries': []}

    while count - len(result) or part['entries']:
        part = interface.search(query=query, filters=filters, sort=sort, offset=len(result), limit=100)
        count = part['count']

        for e in part['entries']:
            entry_id = e['id']

            if entry_id not in result:
                result.add(entry_id)
                yield entry_id


extract_fields = convert(iextract_fields, list)
search_for_ids = convert(isearch_for_ids, list)
